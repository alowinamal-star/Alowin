"""Detection engine for PromptShield AI.

Modules
-------
normalize  : unicode/obfuscation normalisation, language and script detection
patterns   : multilingual rule packs (English, Tamil, Hindi, romanised mixed)
context    : context-aware analysis (quoted / educational vs. real instruction)
features   : sparse feature extraction for the statistical classifier
classifier : hybrid detector combining rules, context and the trained model
risk       : risk scoring, security decision, sanitisation and explanations
extract    : content extraction for PDF/TXT/HTML/email/URL with SSRF guard
firewall   : independent tool-call validation layer
crossdoc   : cross-document (coordinated campaign) analysis
ai_gateway : AI processing stage with untrusted-content isolation contract
"""
