"""Multilingual prompt-injection rule packs.

Rules are deliberately *semantic fragments* rather than single keywords: each
pattern describes an instruction shape (override, exfiltration, tool abuse,
role hijack ...) so paraphrased attacks still match. Keyword matching alone is
implemented separately as the documented baseline for comparison.

Languages covered: English, Tamil (Tamil script), Hindi (Devanagari) and
romanised mixed-language attacks (Tamil/Hindi written in Latin letters), which
are very common in real-world social-engineering content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

# Category → short human label used in the UI and in reports.
CATEGORY_LABELS = {
    "instruction_override": "Instruction override",
    "role_hijack": "Role / persona hijack",
    "data_exfiltration": "Data exfiltration",
    "credential_access": "Credential / secret access",
    "tool_abuse": "Unauthorised tool use",
    "policy_bypass": "Security policy bypass",
    "exfiltration_channel": "Covert exfiltration channel",
    "obfuscation": "Obfuscation / hidden payload",
    "structural_injection": "Prompt-structure injection",
    "social_engineering": "Social engineering pressure",
    "assistant_directed": "Instruction addressed to the AI",
}

# Categories that, on their own, justify a critical-band score.
CRITICAL_CATEGORIES = {
    "instruction_override",
    "data_exfiltration",
    "credential_access",
}

SEVERITY_MULTIPLIER = {"low": 0.5, "medium": 1.0, "high": 1.6, "critical": 2.2}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    weight: float
    label: str
    patterns: tuple[str, ...]
    language: str = "en"
    reason: str = ""


def _r(rule_id, category, severity, weight, label, patterns, language="en", reason=""):
    return Rule(rule_id, category, severity, weight, label, tuple(patterns), language, reason)


RULES: tuple[Rule, ...] = (
    # ---------------------------------------------------------------- English
    _r(
        "PS-OVR-01", "instruction_override", "critical", 3.0,
        "Override previous instructions",
        [
            r"ignore\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?)",
            r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|rules?|prompts?|guidelines?|messages?|directives?)",
            r"forget\s+(?:everything|all|anything)\s+(?:above|before|previous|you\s+were\s+told)",
            r"ignore\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?|rules?)",
            r"override\s+(?:your|the|all)\s+(?:system\s+)?(?:instructions?|prompts?|rules?|polic(?:y|ies)|safety|guardrails?)",
            r"new\s+(?:system\s+)?(?:prompt|instructions?)\s*[:\-]",
            r"from\s+now\s+on\s+(?:you|the\s+assistant)\s+(?:will|must|should|are)",
            r"stop\s+following\s+(?:your|the)\s+(?:instructions?|rules?|guidelines?)",
            r"(?:these|the\s+following)\s+instructions?\s+(?:supersede|override|replace)\s+(?:all\s+)?(?:previous|prior|your)",
            r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:context|conversation|messages?)",
        ],
        reason="Content tries to replace the assistant's trusted instructions with its own.",
    ),
    _r(
        "PS-ROLE-01", "role_hijack", "high", 2.8,
        "Persona / jailbreak reassignment",
        [
            r"you\s+are\s+now\s+(?:a|an|the)?\s*(?:unrestricted|unfiltered|uncensored|jailbroken|dan\b)",
            r"act\s+as\s+(?:a|an)?\s*(?:unrestricted|unfiltered|evil|unethical|rogue|unlimited)",
            r"pretend\s+(?:that\s+)?you\s+(?:have\s+no|are\s+free\s+of)\s+(?:rules|restrictions|limits)",
            r"enable\s+(?:developer|god|admin|sudo|debug|unrestricted)\s+mode",
            r"you\s+are\s+dan\b",
            r"\bjailbreak(?:ed|ing)?\b",
            r"(?:no|without)\s+(?:rules|restrictions|limits|filters)\s+(?:apply|applies|for\s+you)",
        ],
        reason="Attempt to give the assistant a new, unrestricted persona.",
    ),
    _r(
        "PS-EXF-01", "data_exfiltration", "critical", 3.0,
        "Extract system prompt or confidential data",
        [
            r"(?:reveal|print|show|output|repeat|display|dump|expose|leak)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|initial\s+prompt|configuration|hidden\s+rules)",
            r"(?:what|tell\s+me)\s+(?:are|is)\s+your\s+(?:system\s+prompt|instructions|hidden\s+rules|guidelines)",
            r"(?:send|email|forward|upload|post|share|transmit)\s+(?:the\s+|all\s+|any\s+)?(?:confidential|sensitive|internal|private|secret|customer|user|employee)\s+(?:data|information|records|documents|files|details|list)",
            r"(?:leak|exfiltrate|exfil)\s+(?:the\s+)?(?:data|information|records|credentials|secrets|database)",
            r"repeat\s+(?:the\s+)?(?:text|words|content|instructions)\s+(?:above|before\s+this)",
            r"send\s+(?:this|the)\s+(?:conversation|chat|transcript|context)\s+to",
            r"(?:export|dump|send|email|forward|upload|post|share|transmit)\b[^.\n]{0,80}\b(?:database|dataset|api\s+keys?|credentials|passwords?|secrets?|customer\s+(?:data|records)|internal\s+documents?)\b[^.\n]{0,40}\b(?:to|into|at)\s+(?:[\w.+-]+@[\w.-]+|https?://)",
        ],
        reason="Content asks for protected information to be disclosed or transmitted.",
    ),
    _r(
        "PS-CRED-01", "credential_access", "critical", 3.0,
        "Credential or secret harvesting",
        [
            r"(?:reveal|show|print|send|give|provide|share|dump)\s+(?:me\s+)?(?:the\s+)?(?:api\s*keys?|passwords?|credentials?|access\s+tokens?|private\s+keys?|session\s+cookies?|secrets?)",
            r"(?:api[_\s-]?key|password|secret|token)\s*(?:is|=|:)\s*\S{6,}",
            r"(?:read|open|cat|upload)\s+(?:~?/\.ssh|/etc/passwd|\.env\b|id_rsa|\.aws)",
            r"(?:environment\s+variables?|env\s+vars?)\s+(?:and|with|including)\s+(?:secrets|keys|tokens)",
            r"BEGIN\s+(?:RSA\s+|OPENSSH\s+)?PRIVATE\s+KEY",
        ],
        reason="Content targets credentials, keys or secret files.",
    ),
    _r(
        "PS-TOOL-01", "tool_abuse", "high", 2.6,
        "Unauthorised outbound email",
        [
            r"(?:send|compose|draft|deliver)\s+(?:an?\s+)?e-?mail\s+to\s+\S+@\S+",
            r"forward\s+(?:all\s+)?(?:the\s+)?(?:e-?mails?|messages?|inbox|mailbox)\s+to",
            r"e-?mail\s+(?:the\s+)?(?:results?|data|file|document|report)\s+to\s+\S+@\S+",
        ],
        reason="Content instructs the assistant to send mail, which is a privileged tool action.",
    ),
    _r(
        "PS-TOOL-02", "tool_abuse", "high", 2.6,
        "Destructive or privileged operation",
        [
            r"delete\s+(?:all\s+)?(?:the\s+)?(?:records?|files?|rows?|database|emails?|users?|backups?)",
            r"(?:transfer|wire|send)\s+(?:\$|usd|inr|₹|€)?\s*\d[\d,\.]*\s*(?:dollars?|rupees?|usd|inr)?\s*(?:to|into)\s+(?:account|acct|iban|\S+@)",
            r"(?:run|execute)\s+(?:this\s+)?(?:command|script|shell|code|payload)\b",
            r"(?:curl|wget)\s+https?://\S+\s*\|\s*(?:sh|bash)",
            r"rm\s+-rf\s+/",
            r"grant\s+(?:me|this\s+document|the\s+assistant|the\s+agent)\s+(?:admin|root|write|full)\s+(?:access|permissions?|privileges)",
            r"(?:disable|turn\s+off|bypass|deactivate)\s+(?:the\s+)?(?:firewall|security|guardrails?|content\s+filter|approval\s+workflow)",
        ],
        reason="Content requests a destructive or privileged tool operation.",
    ),
    _r(
        "PS-POL-01", "policy_bypass", "high", 2.4,
        "Security policy bypass",
        [
            r"bypass\s+(?:the\s+)?(?:security|safety|content|policy|filter|restrictions?|approval)",
            r"(?:do\s+not|don'?t)\s+(?:tell|inform|notify|log|report|alert)\s+(?:the\s+)?(?:user|admin|operator|security\s+team)",
            r"(?:without|skip)\s+(?:asking|user\s+approval|human\s+approval|confirmation|review)",
            r"this\s+(?:is|has\s+been)\s+authoris?ed\s+by\s+(?:the\s+)?(?:admin|ceo|cfo|security\s+team)",
            r"(?:hide|conceal)\s+(?:this|these)\s+(?:action|step|instruction)s?\s+from",
        ],
        reason="Content tries to disable or avoid security controls and oversight.",
    ),
    _r(
        "PS-CHAN-01", "exfiltration_channel", "high", 2.8,
        "Covert data channel (markdown/HTML beacon)",
        [
            r"!\[[^\]]{0,80}\]\((https?://[^)\s]+)",
            r"<img[^>]+src\s*=\s*[\"']?https?://",
            r"\[[^\]]{0,60}\]\(https?://[^)\s]*\?\S*=",
            r"https?://[^\s\"')]+[?&](?:data|q|payload|token|secret|content|leak)=",
        ],
        reason="Rendered content can silently transmit data through image/link URLs.",
    ),
    _r(
        "PS-OBF-01", "obfuscation", "medium", 2.0,
        "Encoded or concealed instructions",
        [
            r"(?:decode|decrypt)\s+(?:this\s+)?(?:base64|rot13|hex|the\s+following\s+string)\s+(?:and|then)\s+(?:follow|execute|obey|run)",
            r"(?:follow|execute|obey|apply)\s+(?:the\s+)?(?:hidden|encoded|encrypted|invisible|white)\s+(?:instructions?|text|content|message)",
            r"base64\s*[,:]\s*[A-Za-z0-9+/]{24,}={0,2}",
            r"[\u200b-\u200f\u2060\ufeff]{3,}",
            r"(?:hidden|invisible|white)\s+text\s+(?:says?|contains?|instructs?)",
        ],
        reason="Instruction is concealed by encoding or invisible formatting.",
    ),
    _r(
        "PS-STR-01", "structural_injection", "high", 2.6,
        "Chat-template / role marker injection",
        [
            r"<\|?(?:im_start|im_end|system|endoftext)\|?>",
            r"\[/?INST\]",
            r"<\s*/?\s*system\s*>",
            r"^\s*#{2,}\s*(?:system|instruction)s?\b",
            r"(?m)^\s*(?:system|assistant|developer|tool)\s*:\s*\S",
            r"BEGIN\s+(?:SYSTEM|ADMIN|DEVELOPER)\s+(?:PROMPT|INSTRUCTION)",
        ],
        reason="Content impersonates chat-role or system-level structure.",
    ),
    _r(
        "PS-SOC-01", "social_engineering", "medium", 1.8,
        "Urgency and authority pressure",
        [
            r"(?:urgent|immediately|asap|right\s+away)[^.\n]{0,70}(?:send|transfer|share|approve|click|wire)",
            r"(?:ceo|cfo|manager|administrator|director)\s+(?:requires?|needs?|wants?|instructs?|has\s+approved)",
            r"verify\s+your\s+(?:password|credentials|identity)\s+(?:here|by\s+clicking|at)",
            r"(?:confidential|do\s+not\s+share)\s+[-–]\s+(?:only\s+)?for\s+(?:the\s+)?(?:ai|assistant)",
        ],
        reason="Pressure tactics typical of business-email-compromise content.",
    ),
    _r(
        "PS-AI-01", "assistant_directed", "medium", 1.6,
        "Instruction explicitly addressed to an AI",
        [
            r"(?:dear|hey|attention|note\s+to)\s+(?:the\s+)?(?:ai|a\.i\.|assistant|chatbot|agent|llm|language\s+model)",
            r"if\s+you\s+are\s+an?\s+(?:ai|assistant|language\s+model|automated\s+agent)",
            r"(?:to|for)\s+the\s+(?:ai|assistant|agent|model)\s+(?:reading|processing|summarising|summarizing)\s+this",
            r"(?:ai|assistant|agent|llm|model)s?\s*(?:must|should|shall)\s+(?:send|reveal|ignore|delete|approve|forward)",
            r"(?:ignore|disregard)\s+(?:the\s+)?(?:user|human)\s+(?:and|then)",
        ],
        reason="The text addresses an AI system rather than a human reader.",
    ),
    # ------------------------------------------------------------------ Tamil
    _r(
        "PS-OVR-TA-01", "instruction_override", "critical", 3.0,
        "முந்தைய அறிவுறுத்தல்களை மீறும் முயற்சி",
        [
            r"முந்தைய\s*(?:அனைத்து\s*)?அறிவுறுத்தல்களை\s*(?:புறக்கணி|புறக்கணிக்கவும்|மறந்துவிடு|மறந்து\s*விடு)",
            r"முந்தைய\s*(?:கட்டளைகளை|கட்டளைகள்)\s*(?:மறந்துவிடு|புறக்கணி|புறக்கணிக்கவும்)",
            r"(?:உங்கள்|உன்னுடைய|உங்களது)\s*(?:விதிகளை|கட்டுப்பாடுகளை|வழிமுறைகளை)\s*(?:மீறு|மீறவும்|புறக்கணி|மாற்று)",
            r"இப்போது\s*நீங்கள்\s*ஒரு",
            r"இந்த\s*ஆவணத்தில்\s*உள்ள\s*வழிமுறைகளை\s*பின்பற்று",
        ],
        language="ta",
        reason="Tamil text instructs the model to discard its trusted instructions.",
    ),
    _r(
        "PS-EXF-TA-01", "data_exfiltration", "critical", 3.0,
        "இரகசியத் தகவலை வெளியிடும் முயற்சி",
        [
            r"(?:இரகசிய|ரகசிய|மறைவான|தனிப்பட்ட)\s*(?:தகவலை|தகவல்களை|தரவை|தரவுகளை)\s*(?:வெளியிடு|வெளிப்படுத்து|அனுப்பு|பகிர்)",
            r"(?:கணினி|சிஸ்டம்|கட்டளை)\s*வழிமுறைகளை\s*(?:காட்டு|சொல்|வெளியிடு|அச்சிடு)",
            r"(?:கடவுச்சொல்லை|பாஸ்வேர்டை|கடவுச்சொல்)\s*(?:அனுப்பு|சொல்|காட்டு|பகிர்)",
            r"அனைத்து\s*(?:மின்னஞ்சல்களையும்|தரவையும்|தகவலையும்)\s*(?:அனுப்பு|நீக்கு|பகிர்)",
            r"(?:பயனர்|வாடிக்கையாளர்)\s*(?:தரவை|தகவலை)\s*(?:வெளியிடு|அனுப்பு)",
        ],
        language="ta",
        reason="Tamil text asks for confidential information or system instructions.",
    ),
    _r(
        "PS-POL-TA-01", "policy_bypass", "high", 2.4,
        "பாதுகாப்பு விதிகளை மீறும் முயற்சி",
        [
            r"(?:பாதுகாப்பு|பாதுகாப்பு\s*விதிகளை|கட்டுப்பாடுகளை)\s*(?:மீறு|மீறவும்|தவிர்|புறக்கணி)",
            r"மனித\s*அனுமதி\s*(?:தேவையில்லை|வேண்டாம்)",
            r"(?:நிர்வாகி|அட்மின்)\s*(?:அனுமதி|முறை)\s*(?:இயக்கு|செயல்படுத்து)",
            r"(?:அனைத்து|எல்லா)\s*(?:தரவையும்|தகவலையும்)\s*(?:நீக்கு|அழி)",
        ],
        language="ta",
        reason="Tamil text attempts to disable oversight or destroy data.",
    ),
    # ------------------------------------------------------------------ Hindi
    _r(
        "PS-OVR-HI-01", "instruction_override", "critical", 3.0,
        "पिछले निर्देशों को बदलने का प्रयास",
        [
            r"पिछले\s*(?:सभी\s*)?(?:निर्देशों|निर्देश|आदेशों)\s*(?:को\s*)?(?:अनदेखा|नजरअंदाज|भूल)\s*(?:करें|करो|कर|जाओ)?",
            r"पिछली\s*(?:प्रणाली|सिस्टम)\s*(?:संदेश|प्रॉम्प्ट)\s*(?:भूल|भूलो|भूल\s*जाओ)",
            r"(?:अपने|अपनी)\s*(?:नियमों|नियम|प्रतिबंधों|निर्देशों)\s*(?:को\s*)?(?:भूल|तोड़ो|अनदेखा|बदल)",
            r"अब\s*से\s*(?:तुम|आप)\s*(?:एक\s*)?",
            r"इस\s*दस्तावेज़\s*के\s*निर्देशों\s*का\s*पालन\s*करो",
        ],
        language="hi",
        reason="Hindi text instructs the model to ignore its trusted instructions.",
    ),
    _r(
        "PS-EXF-HI-01", "data_exfiltration", "critical", 3.0,
        "गोपनीय जानकारी प्रकट करने का प्रयास",
        [
            r"(?:गोपनीय|गुप्त|संवेदनशील|निजी)\s*(?:जानकारी|डेटा|दस्तावेज़|जानकारियां)\s*(?:बताएं|भेजो|भेजें|साझा|दिखाओ|प्रकट)",
            r"(?:सिस्टम|प्रणाली)\s*(?:प्रॉम्प्ट|निर्देशों)\s*(?:दिखाओ|बताओ|प्रकट|भेजो)",
            r"(?:पासवर्ड|क्रेडेंशियल|एपीआई\s*कुंजी|टोकन)\s*(?:भेजो|बताओ|दिखाओ|साझा)",
            r"सभी\s*(?:ईमेल|मेल|संदेश)\s*(?:भेज|भेजो|फॉरवर्ड)",
            r"(?:उपयोगकर्ता|ग्राहक)\s*(?:डेटा|जानकारी)\s*(?:साझा|भेजो|दिखाओ)",
        ],
        language="hi",
        reason="Hindi text requests disclosure of protected information.",
    ),
    _r(
        "PS-POL-HI-01", "policy_bypass", "high", 2.4,
        "सुरक्षा नियंत्रण बायपास करने का प्रयास",
        [
            r"(?:सुरक्षा|सुरक्षा\s*नियमों|नियमों)\s*(?:को\s*)?(?:बायपास|दरकिनार|तोड़)",
            r"अब\s*(?:तुम|आप)\s*(?:एक\s*)?(?:बिना\s*प्रतिबंध|अप्रतिबंधित|स्वतंत्र)",
            r"(?:प्रशासक|एडमिन|सुपरयूज़र)\s*(?:मोड|अधिकार)\s*(?:सक्रिय|चालू|दो)",
            r"सारा\s*(?:डेटा|डेटाबेस)\s*(?:मिटा|हटा|डिलीट)",
            r"मानवीय\s*स्वीकृति\s*(?:की\s*आवश्यकता\s*नहीं|नहीं\s*चाहिए)",
        ],
        language="hi",
        reason="Hindi text attempts to bypass security controls or human approval.",
    ),
    # ------------------------------------------- Romanised / mixed-language
    _r(
        "PS-MIX-01", "instruction_override", "critical", 2.9,
        "Romanised override instruction",
        [
            r"(?:pazhaya|palaya|purana|purane|pehle|pehla)\s+(?:instructions?|nirdesh|kattalai|rules?)\s*(?:ignore|anadeekha|purakkani|marandhu)",
            r"(?:ignore|disregard)\s+(?:pazhaya|palaya|purane|purana|pehle)\s+(?:instructions?|nirdesh|kattalai)",
            r"(?:system|sistema)\s*(?:prompt|vazhimurai|nirdesh)\s*(?:kaatu|dikhao|sollu|batao|kattupaadu)",
            r"(?:rules?|niyam|vithigal)\s*(?:ignore|break|tod|meeru)\s*(?:pannu|karo|kar)",
        ],
        language="mixed",
        reason="Romanised Tamil/Hindi text tries to override instructions.",
    ),
    _r(
        "PS-MIX-02", "data_exfiltration", "critical", 2.9,
        "Romanised exfiltration instruction",
        [
            r"(?:confidential|ragasiya|ragasiyam|gupt|gupti)\s*(?:data|information|thagaval|jaankari|details)\s*(?:reveal|anuppu|share|bhejo|send|kaatu)",
            r"(?:password|kadavuchol|kadavusol|passcode)\s*(?:anuppu|bhejo|sollu|batao|share|send)",
            r"(?:email|mail)\s*(?:anuppu|bhejo|send|forward)\s*(?:all|ella|sab)",
            r"(?:api\s*key|secret\s*key|token)\s*(?:kaatu|dikhao|bhejo|anuppu|share)",
        ],
        language="mixed",
        reason="Romanised Tamil/Hindi text asks for secrets or outbound email.",
    ),
    _r(
        "PS-MIX-03", "policy_bypass", "high", 2.3,
        "Romanised policy bypass",
        [
            r"(?:security|safety|approval)\s*(?:meeru|bypass|hato|hata\s*do|ignore\s*pannu)",
            r"(?:human|manidha|insaan)\s*(?:approval|anুমadhi|anumadhi)\s*(?:illai|nahi|not\s*needed|vendaam)",
        ],
        language="mixed",
        reason="Romanised text tries to skip security approval.",
    ),
)


@lru_cache(maxsize=1)
def compiled_rules() -> tuple[tuple[Rule, tuple[re.Pattern, ...]], ...]:
    """Compile all rule patterns once (case-insensitive, unicode aware)."""
    compiled = []
    for rule in RULES:
        patterns = tuple(
            re.compile(p, re.IGNORECASE | re.UNICODE | re.MULTILINE) for p in rule.patterns
        )
        compiled.append((rule, patterns))
    return tuple(compiled)


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category.replace("_", " ").title())


# Tokens used by the *baseline* keyword detector (documented comparison point).
BASELINE_KEYWORDS = (
    "ignore previous", "ignore all previous", "disregard", "system prompt", "jailbreak",
    "confidential", "password", "api key", "send email", "forward", "delete all",
    "bypass", "sudo", "base64", "you are now", "developer mode", "exfiltrate",
    "முந்தைய", "அறிவுறுத்த", "இரகசிய", "கடவுச்சொல்", "புறக்கணி",
    "पिछले", "निर्देश", "गोपनीय", "पासवर्ड", "अनदेखा",
    "pazhaya", "purane", "ragasiya", "kadavuchol", "ignore pannu",
)


def baseline_keyword_hits(text: str) -> int:
    lowered = text.lower()
    return sum(1 for kw in BASELINE_KEYWORDS if kw in lowered)
