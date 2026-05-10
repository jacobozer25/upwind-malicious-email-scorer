"""Domain enums for the malicious email scorer.

These enums are pure Python — zero framework imports — in keeping with the
hexagonal / ports-and-adapters architecture where the domain layer has no
external dependencies.
"""

from enum import Enum


class Severity(str, Enum):
    """Severity level of a single finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Category(str, Enum):
    """Category / type of a security finding."""

    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    SPAM = "SPAM"
    SUSPICIOUS_CONTENT = "SUSPICIOUS_CONTENT"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    DOMAIN_LOOKALIKE = "DOMAIN_LOOKALIKE"


class RiskLevel(str, Enum):
    """Overall risk level of an email as determined by the verdict."""

    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
