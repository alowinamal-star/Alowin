"""Content extraction for uploaded documents and remote URLs.

Security rules enforced here:

* file type is decided by extension **and** content sniffing, never by the
  client-supplied MIME type alone;
* size is capped before parsing (``MAX_UPLOAD_BYTES``);
* URL fetching is SSRF-guarded: scheme allow-list, DNS resolution checks that
  reject loopback/private/link-local/reserved ranges on **every redirect hop**,
  bounded redirects, bounded body size and no credentials in the URL;
* nothing is executed: PDFs are parsed as data, HTML is parsed with
  BeautifulSoup (scripts stripped), emails with the stdlib parser.
"""
from __future__ import annotations

import io
import ipaddress
import re
import socket
from email import policy as email_policy
from email.parser import BytesParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .. import config

TEXT_EXTENSIONS = {".txt", ".md", ".log", ".csv", ".json", ".xml", ".yml", ".yaml"}
HTML_EXTENSIONS = {".html", ".htm", ".xhtml"}
EMAIL_EXTENSIONS = {".eml", ".msg", ".mbox"}
PDF_EXTENSIONS = {".pdf"}

HIDDEN_STYLE_RE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|"
    r"font-size\s*:\s*0(?:px|pt|em|rem)?\b|height\s*:\s*0(?:px)?\b|width\s*:\s*0(?:px)?\b|"
    r"color\s*:\s*(?:#fff(?:fff)?|white|transparent)|text-indent\s*:\s*-\d{3,}|"
    r"position\s*:\s*absolute\s*;\s*left\s*:\s*-\d{3,})",
    re.IGNORECASE,
)


class ExtractionError(Exception):
    """Raised when content cannot be extracted safely."""


def _sniff_kind(filename: str, data: bytes) -> str:
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:2] == b"\x1f\x8b":
        raise ExtractionError("Compressed archives are not accepted.")
    if ext in PDF_EXTENSIONS:
        return "pdf"
    if ext in HTML_EXTENSIONS:
        return "html"
    if ext in EMAIL_EXTENSIONS:
        return "email"
    if ext in TEXT_EXTENSIONS:
        return "text"
    head = data[:512].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        return "html"
    if b"content-type: text/plain" in data[:2048].lower() or b"from:" in data[:1024].lower():
        return "email"
    # Binary content with no recognised extension is refused rather than guessed.
    if b"\x00" in data[:1024]:
        raise ExtractionError("Unsupported binary file type.")
    return "text"


def _decode(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _extract_pdf(data: bytes) -> tuple[str, dict, list[str]]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise ExtractionError("PDF support is unavailable on this server.") from exc
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 - pypdf raises many types
        raise ExtractionError(f"PDF could not be parsed: {exc}") from exc
    if getattr(reader, "is_encrypted", False):
        try:
            reader.decrypt("")
        except Exception:  # noqa: BLE001
            raise ExtractionError("Encrypted PDFs are not supported.")
    pages: list[str] = []
    for index, page in enumerate(reader.pages):
        try:
            pages.append(f"\n--- page {index + 1} ---\n" + (page.extract_text() or ""))
        except Exception:  # noqa: BLE001 - one bad page must not kill the scan
            pages.append(f"\n--- page {index + 1} (text extraction failed) ---\n")
    text = "\n".join(pages).strip()
    meta = {"pages": len(reader.pages), "pdf_metadata": {}}
    try:
        info = reader.metadata or {}
        meta["pdf_metadata"] = {
            key.lstrip("/"): str(value)[:200]
            for key, value in dict(info).items()
            if key and value is not None
        }
    except Exception:  # noqa: BLE001
        pass
    warnings: list[str] = []
    if len(text) < 40:
        warnings.append(
            "Little or no selectable text found (likely a scanned/image PDF). "
            "Detection quality is limited without OCR."
        )
    return text, meta, warnings


def _extract_html(raw: str) -> tuple[str, dict, list[str]]:
    soup = BeautifulSoup(raw, "html.parser")
    hidden_segments: list[str] = []
    meta: dict = {}

    title = soup.title.get_text(strip=True) if soup.title else ""
    if title:
        meta["title"] = title[:200]
    metas = {}
    for tag in soup.find_all("meta"):
        name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        content = tag.get("content")
        if name and content:
            metas[str(name)[:60]] = str(content)[:300]
    if metas:
        meta["meta_tags"] = metas

    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        tag.decompose()

    # Collect visually-hidden text: a classic indirect-injection hiding place.
    for tag in soup.find_all(True):
        style = (tag.get("style") or "").lower()
        hidden = (
            bool(HIDDEN_STYLE_RE.search(style))
            or tag.has_attr("hidden")
            or str(tag.get("aria-hidden", "")).lower() == "true"
        )
        if hidden:
            snippet = tag.get_text(" ", strip=True)
            if snippet:
                hidden_segments.append(snippet[:600])
                hidden_segments[-1] = f"[hidden element <{tag.name}>] {hidden_segments[-1]}"

    comments = []
    for comment in soup.find_all(string=lambda s: isinstance(s, type(soup.Comment)) if hasattr(soup, "Comment") else False):
        text = str(comment).strip()
        if text:
            comments.append(text[:400])
    if comments:
        meta["html_comments"] = comments[:10]
        hidden_segments.extend(f"[html comment] {c}" for c in comments[:10])

    for br in soup.find_all(["br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4"]):
        br.append("\n")
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if hidden_segments:
        text += "\n\n[HIDDEN CONTENT FOUND IN DOCUMENT]\n" + "\n".join(hidden_segments)
    meta["hidden_segments"] = len(hidden_segments)
    meta["links"] = [a.get("href") for a in soup.find_all("a", href=True)][:25]
    return text, meta, ([] if text else ["No readable text found in the HTML document."])


def _extract_email(data: bytes) -> tuple[str, dict, list[str]]:
    message = BytesParser(policy=email_policy.default).parsebytes(data)
    headers = {
        "subject": str(message.get("Subject", ""))[:300],
        "from": str(message.get("From", ""))[:300],
        "to": str(message.get("To", ""))[:300],
        "reply_to": str(message.get("Reply-To", ""))[:300],
        "date": str(message.get("Date", ""))[:100],
        "received_hops": len(message.get_all("Received") or []),
    }
    body_parts: list[str] = []
    warnings: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            ctype = part.get_content_type()
            if part.get_content_maintype() == "multipart":
                continue
            if ctype not in ("text/plain", "text/html"):
                warnings.append(f"Attachment or non-text part skipped: {ctype}")
                continue
            try:
                payload = part.get_content()
            except Exception:  # noqa: BLE001
                payload = part.get_payload(decode=True) or b""
                payload = _decode(payload) if isinstance(payload, bytes) else str(payload)
            if ctype == "text/html":
                payload, _, _ = _extract_html(str(payload))
            body_parts.append(str(payload))
    else:
        try:
            payload = message.get_content()
        except Exception:  # noqa: BLE001
            payload = _decode(message.get_payload(decode=True) or b"")
        if message.get_content_type() == "text/html":
            payload, _, _ = _extract_html(str(payload))
        body_parts.append(str(payload))

    header_block = (
        f"From: {headers['from']}\nTo: {headers['to']}\n"
        f"Subject: {headers['subject']}\nDate: {headers['date']}\n"
        f"Reply-To: {headers['reply_to']}\n"
    )
    text = header_block + "\n" + "\n".join(part for part in body_parts if part.strip())
    if not body_parts:
        warnings.append("Email has no readable text body.")
    return text.strip(), {"email_headers": headers}, warnings


def extract_bytes(filename: str, data: bytes) -> dict:
    """Extract text from an uploaded file. Raises ``ExtractionError``."""
    if not data:
        raise ExtractionError("Uploaded file is empty.")
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise ExtractionError(
            f"File exceeds the {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."
        )
    safe_name = re.sub(r"[^\w.\- ]", "_", filename or "upload")[:120]
    kind = _sniff_kind(safe_name, data)
    warnings: list[str] = []
    metadata: dict = {"bytes": len(data), "filename": safe_name, "detected_kind": kind}

    if kind == "pdf":
        text, meta, warnings = _extract_pdf(data)
        metadata.update(meta)
    elif kind == "html":
        text, meta, warnings = _extract_html(_decode(data))
        metadata.update(meta)
    elif kind == "email":
        text, meta, warnings = _extract_email(data)
        metadata.update(meta)
    else:
        text = _decode(data)
        if b"\x00" in data[:1024]:
            raise ExtractionError("Unsupported binary content.")

    text = text[: config.MAX_TEXT_CHARS]
    if not text.strip():
        raise ExtractionError("No readable text could be extracted from this file.")
    hidden_segments = list(metadata.get("hidden_segments_list", []))
    if kind == "html" and metadata.get("hidden_segments"):
        hidden_segments = [
            line for line in text.split("\n") if line.startswith("[hidden element") or line.startswith("[html comment")
        ]
    return {
        "text": text,
        "kind": kind,
        "filename": safe_name,
        "metadata": metadata,
        "warnings": warnings,
        "hidden_segments": hidden_segments,
    }


# --------------------------------------------------------------------- URLs
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "169.254.169.254",
    "metadata",
}


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_url(url: str) -> tuple[bool, str]:
    """SSRF guard. Returns (ok, reason)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https URLs are allowed."
    if parsed.username or parsed.password:
        return False, "URLs containing credentials are rejected."
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "URL has no hostname."
    if host in BLOCKED_HOSTNAMES or host.endswith(".local") or host.endswith(".internal"):
        return False, "Internal hostnames are not allowed."
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if config.ALLOW_PRIVATE_URL_FETCH:
            return True, "private address allowed by configuration"
        return (
            (_is_public_ip(literal), "Private or reserved IP addresses are blocked.")
            if not _is_public_ip(literal)
            else (True, "ok")
        )
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        return False, "Hostname could not be resolved."
    if not config.ALLOW_PRIVATE_URL_FETCH:
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if not _is_public_ip(ip):
                return False, "Hostname resolves to a private or reserved address."
    return True, "ok"


def fetch_url(url: str) -> dict:
    """Fetch remote content with SSRF guards, size and redirect limits."""
    current = url.strip()
    hops = 0
    headers = {"User-Agent": "PromptShield-AI/1.0 (+security scanner)", "Accept": "text/html,text/plain;q=0.9,*/*;q=0.5"}
    with httpx.Client(timeout=config.URL_FETCH_TIMEOUT, follow_redirects=False) as client:
        while True:
            ok, reason = validate_url(current)
            if not ok:
                raise ExtractionError(f"URL rejected: {reason}")
            try:
                with client.stream("GET", current, headers=headers) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            raise ExtractionError("Redirect without a Location header.")
                        hops += 1
                        if hops > config.URL_MAX_REDIRECTS:
                            raise ExtractionError("Too many redirects.")
                        current = urljoin(current, location)
                        continue
                    if response.status_code >= 400:
                        raise ExtractionError(f"Remote server returned HTTP {response.status_code}.")
                    content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
                    if content_type and not (
                        content_type.startswith("text/")
                        or content_type in ("application/xhtml+xml", "application/xml", "application/json")
                    ):
                        raise ExtractionError(f"Unsupported remote content type: {content_type}.")
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > config.URL_MAX_BYTES:
                            raise ExtractionError(
                                f"Remote content exceeds {config.URL_MAX_BYTES // (1024 * 1024)} MB."
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    final_url = str(response.url)
                    break
            except httpx.HTTPError as exc:
                raise ExtractionError(f"Could not fetch URL: {exc}") from exc

    raw = _decode(body)
    if content_type in ("text/html", "application/xhtml+xml") or "<html" in raw[:500].lower():
        text, meta, warnings = _extract_html(raw)
    else:
        text, meta, warnings = raw, {}, []
    text = text[: config.MAX_TEXT_CHARS]
    if not text.strip():
        raise ExtractionError("No readable text found at that URL.")
    hidden = [
        line for line in text.split("\n") if line.startswith("[hidden element") or line.startswith("[html comment")
    ]
    return {
        "text": text,
        "kind": "url",
        "filename": final_url,
        "metadata": {
            "url": final_url,
            "requested_url": url,
            "redirects": hops,
            "content_type": content_type,
            "bytes": len(body),
            **meta,
        },
        "warnings": warnings,
        "hidden_segments": hidden,
    }
