import re
import logging

# Compiled regex patterns for speed (spec §9.7)
AUTHORIZATION_RE = re.compile(
    r'(?i)(authorization\s*:\s*)(?:bearer|basic)\s+[a-zA-Z0-9\-_=\.\+/~]+',
)
BEARER_RE = re.compile(
    r'(?i)(bearer\s+)[a-zA-Z0-9\-_=\.\+/~]+',
)
AMZ_SIGNATURE_RE = re.compile(
    r'(?i)(x-amz-signature\s*=\s*)[a-fA-F0-9]+',
)
SIGNATURE_RE = re.compile(
    r'(?i)(signature\s*=\s*)[a-fA-F0-9]+',
)
TELEGRAM_SESSION_RE = re.compile(
    r'(?i)(telethon_session\s*:\s*)[a-zA-Z0-9\-_=\.\+/~]+',
)
EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
)
TELEGRAM_BOT_TOKEN_RE = re.compile(
    r'\b\d{8,10}:[a-zA-Z0-9_\-]{35}\b',
)
URL_CREDENTIALS_RE = re.compile(
    r'(?i)(://[^:]+:)[^@]+@',
)

def sanitize_for_log(text: str) -> str:
    """
    Sanitize sensitive fields from log messages and API responses (spec §9.7).
    """
    if not isinstance(text, str):
        return text

    text = AUTHORIZATION_RE.sub(r'\1[REDACTED]', text)
    text = BEARER_RE.sub(r'\1[REDACTED]', text)
    text = AMZ_SIGNATURE_RE.sub(r'\1[REDACTED]', text)
    text = SIGNATURE_RE.sub(r'\1[REDACTED]', text)
    text = TELEGRAM_SESSION_RE.sub(r'\1[REDACTED]', text)
    text = EMAIL_RE.sub('[REDACTED_EMAIL]', text)
    text = TELEGRAM_BOT_TOKEN_RE.sub('[REDACTED_TELEGRAM_TOKEN]', text)
    text = URL_CREDENTIALS_RE.sub(r'\1[REDACTED]@', text)
    return text


class SanitizedFormatter(logging.Formatter):
    """
    Logging formatter that automatically sanitizes all formatted log records (spec §9.7).
    """
    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return sanitize_for_log(formatted)
