"""
backend/app/analyzers/attachments.py
--------------------------------------
Deterministic attachment metadata analyzer for the malicious email scorer.

This analyzer inspects the ``attachment_metadata`` list on an
:class:`~app.domain.models.EmailContext` for two classes of signals:

1. **MIME / extension mismatch** — the declared MIME type does not match the
   file extension.  Attackers rename executables as ``.pdf`` or ``.docx`` to
   bypass naive filters.

2. **Suspicious filename patterns** — filenames that combine social-engineering
   keywords (e.g. "invoice", "payment", "urgent") with dangerous extensions
   (e.g. ``.exe``, ``.js``, ``.vbs``), or filenames that use double extensions
   (e.g. ``report.pdf.exe``).

Design notes
============
* No network calls and no file I/O — only metadata is inspected.
* Attachment *bytes* are never stored in ``EmailContext``; magic-byte analysis
  would require bytes and is therefore out of scope for this module.
* All findings use ``Category.MALWARE`` (extension/MIME mismatch) or
  ``Category.SUSPICIOUS_CONTENT`` (social-engineering filename patterns).
* Implements :class:`~app.domain.ports.AnalyzerPort`.
"""
from __future__ import annotations

import re
from typing import Any, Final

from app.domain.enums import Category, Severity
from app.domain.models import EmailContext, Finding
from app.domain.ports import AnalyzerPort

# ---------------------------------------------------------------------------
# Extension → expected MIME type(s) mapping
# ---------------------------------------------------------------------------
# Maps lowercase file extension (without leading dot) to the set of MIME types
# that are considered legitimate for that extension.  Any other MIME type is
# flagged as a mismatch.

_EXT_TO_MIME: Final[dict[str, frozenset[str]]] = {
    "pdf": frozenset({"application/pdf"}),
    "doc": frozenset({"application/msword"}),
    "docx": frozenset(
        {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",  # OOXML is a ZIP container
        }
    ),
    "xls": frozenset({"application/vnd.ms-excel"}),
    "xlsx": frozenset(
        {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/zip",
        }
    ),
    "ppt": frozenset({"application/vnd.ms-powerpoint"}),
    "pptx": frozenset(
        {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/zip",
        }
    ),
    "zip": frozenset({"application/zip", "application/x-zip-compressed"}),
    "gz": frozenset({"application/gzip", "application/x-gzip"}),
    "tar": frozenset({"application/x-tar"}),
    "7z": frozenset({"application/x-7z-compressed"}),
    "rar": frozenset({"application/x-rar-compressed", "application/vnd.rar"}),
    "jpg": frozenset({"image/jpeg"}),
    "jpeg": frozenset({"image/jpeg"}),
    "png": frozenset({"image/png"}),
    "gif": frozenset({"image/gif"}),
    "svg": frozenset({"image/svg+xml"}),
    "txt": frozenset({"text/plain"}),
    "csv": frozenset({"text/csv", "text/plain"}),
    "html": frozenset({"text/html"}),
    "htm": frozenset({"text/html"}),
    "xml": frozenset({"application/xml", "text/xml"}),
    "json": frozenset({"application/json"}),
    "mp3": frozenset({"audio/mpeg"}),
    "mp4": frozenset({"video/mp4"}),
    "exe": frozenset({"application/x-msdownload", "application/octet-stream"}),
    "dll": frozenset({"application/x-msdownload", "application/octet-stream"}),
    "js": frozenset({"application/javascript", "text/javascript"}),
    "vbs": frozenset({"text/vbscript"}),
    "ps1": frozenset({"text/plain", "application/octet-stream"}),
    "bat": frozenset({"text/plain", "application/octet-stream"}),
    "sh": frozenset({"text/x-sh", "application/x-sh", "text/plain"}),
}

# ---------------------------------------------------------------------------
# Dangerous / executable extensions
# ---------------------------------------------------------------------------
# Extensions that are inherently high-risk regardless of MIME type.

_DANGEROUS_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        "exe", "dll", "com", "bat", "cmd", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "msi", "msp", "ps1", "ps2", "psc1", "psc2",
        "reg", "scr", "hta", "cpl", "inf", "lnk", "pif", "jar",
        "apk", "ipa", "dmg", "pkg", "deb", "rpm",
        "py", "rb", "pl", "php",  # Script files — suspicious in email
    }
)

# ---------------------------------------------------------------------------
# Social-engineering keyword patterns in filenames
# ---------------------------------------------------------------------------
# Patterns that, when combined with a dangerous extension, indicate a
# social-engineering lure.

_LURE_KEYWORDS_RE: Final[re.Pattern[str]] = re.compile(
    r"\b("
    r"invoice|invoic|inv[_\-]?\d|"
    r"payment|pay[_\-]?slip|remittance|receipt|"
    r"urgent|important|action[_\-]?required|"
    r"statement|bank[_\-]?statement|account[_\-]?statement|"
    r"order|purchase[_\-]?order|po[_\-]?\d|"
    r"contract|agreement|nda|"
    r"resume|cv|curriculum[_\-]?vitae|"
    r"refund|compensation|claim|"
    r"notification|alert|warning|"
    r"document|doc[_\-]?\d|file[_\-]?\d|"
    r"scan|scanned|fax|"
    r"delivery|shipment|tracking|dhl|fedex|ups|usps"
    r")\b",
    re.IGNORECASE,
)

# Double-extension pattern: e.g. "report.pdf.exe", "photo.jpg.vbs"
_DOUBLE_EXT_RE: Final[re.Pattern[str]] = re.compile(
    r"\.[a-zA-Z0-9]{2,5}\.[a-zA-Z0-9]{2,5}$"
)

# ---------------------------------------------------------------------------
# MIME type → extension mismatch detection helpers
# ---------------------------------------------------------------------------

# MIME types that are always suspicious regardless of extension
_ALWAYS_SUSPICIOUS_MIMES: Final[frozenset[str]] = frozenset(
    {
        "application/x-msdownload",
        "application/x-executable",
        "application/x-dosexec",
        "application/x-msdos-program",
    }
)


def _get_extension(filename: str) -> str:
    """Return the lowercase extension (without dot) of a filename."""
    parts = filename.rsplit(".", 1)
    return parts[-1].lower() if len(parts) == 2 else ""


def _normalize_mime(mime: str) -> str:
    """Strip parameters (e.g. charset) from a MIME type string."""
    return mime.split(";")[0].strip().lower()


# ---------------------------------------------------------------------------
# AttachmentsAnalyzer
# ---------------------------------------------------------------------------


class AttachmentsAnalyzer(AnalyzerPort):
    """Deterministic attachment metadata analyzer.

    Checks each entry in :attr:`~app.domain.models.EmailContext.attachment_metadata`
    for MIME/extension mismatches and social-engineering filename patterns.

    Implements :class:`~app.domain.ports.AnalyzerPort`.
    """

    async def analyze(self, context: EmailContext) -> list[Finding]:
        """Analyze attachment metadata for suspicious signals.

        Args:
            context: The :class:`~app.domain.models.EmailContext` to analyze.

        Returns:
            A list of :class:`~app.domain.models.Finding` objects.
        """
        findings: list[Finding] = []

        for meta in context.attachment_metadata:
            findings.extend(self._analyze_attachment(meta))

        return findings

    # ------------------------------------------------------------------
    # Per-attachment checks
    # ------------------------------------------------------------------

    def _analyze_attachment(self, meta: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        filename: str = str(meta.get("filename") or "").strip()
        mime_type: str = str(meta.get("mime_type") or "").strip()
        size_bytes: int = int(meta.get("size_bytes") or 0)

        if not filename:
            return findings

        findings.extend(self._check_mime_mismatch(filename, mime_type, meta))
        findings.extend(self._check_dangerous_extension(filename, mime_type, meta))
        findings.extend(self._check_double_extension(filename, meta))
        findings.extend(self._check_lure_filename(filename, meta))
        findings.extend(self._check_suspicious_size(filename, mime_type, size_bytes, meta))

        return findings

    # ------------------------------------------------------------------
    # MIME / extension mismatch
    # ------------------------------------------------------------------

    @staticmethod
    def _check_mime_mismatch(
        filename: str, mime_type: str, meta: dict[str, Any]
    ) -> list[Finding]:
        if not mime_type:
            return []

        ext = _get_extension(filename)
        normalized_mime = _normalize_mime(mime_type)

        # Always-suspicious MIME types
        if normalized_mime in _ALWAYS_SUSPICIOUS_MIMES:
            return [
                Finding(
                    type=Category.MALWARE,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Attachment '{filename}' has a MIME type "
                        f"'{normalized_mime}' that indicates an executable. "
                        "This is a strong malware delivery signal."
                    ),
                    evidence={
                        "signal": "always_suspicious_mime",
                        "filename": filename,
                        "mime_type": normalized_mime,
                        "size_bytes": meta.get("size_bytes"),
                    },
                )
            ]

        if not ext or ext not in _EXT_TO_MIME:
            return []

        expected_mimes = _EXT_TO_MIME[ext]
        if normalized_mime not in expected_mimes:
            # Determine severity: executable MIME masquerading as benign ext is CRITICAL
            severity = (
                Severity.CRITICAL
                if normalized_mime in _ALWAYS_SUSPICIOUS_MIMES
                or any(
                    dangerous in normalized_mime
                    for dangerous in ("executable", "msdownload", "dosexec")
                )
                else Severity.HIGH
            )
            return [
                Finding(
                    type=Category.MALWARE,
                    severity=severity,
                    description=(
                        f"MIME type mismatch for attachment '{filename}': "
                        f"extension '.{ext}' suggests {list(expected_mimes)[:1][0]!r} "
                        f"but declared MIME type is '{normalized_mime}'. "
                        "This is a common technique to disguise malicious files."
                    ),
                    evidence={
                        "signal": "mime_extension_mismatch",
                        "filename": filename,
                        "extension": ext,
                        "declared_mime": normalized_mime,
                        "expected_mimes": sorted(expected_mimes),
                        "size_bytes": meta.get("size_bytes"),
                    },
                )
            ]

        return []

    # ------------------------------------------------------------------
    # Dangerous extension check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dangerous_extension(
        filename: str, mime_type: str, meta: dict[str, Any]
    ) -> list[Finding]:
        ext = _get_extension(filename)
        if ext not in _DANGEROUS_EXTENSIONS:
            return []

        # Script/executable extensions are always high-risk in email
        severity = (
            Severity.CRITICAL
            if ext in {"exe", "dll", "com", "bat", "cmd", "vbs", "vbe", "js", "jse",
                       "wsf", "wsh", "msi", "scr", "hta", "pif", "lnk"}
            else Severity.HIGH
        )

        return [
            Finding(
                type=Category.MALWARE,
                severity=severity,
                description=(
                    f"Attachment '{filename}' has a dangerous file extension '.{ext}'. "
                    "Executable and script files delivered via email are a primary "
                    "malware delivery vector."
                ),
                evidence={
                    "signal": "dangerous_extension",
                    "filename": filename,
                    "extension": ext,
                    "mime_type": mime_type or None,
                    "size_bytes": meta.get("size_bytes"),
                },
            )
        ]

    # ------------------------------------------------------------------
    # Double extension check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_double_extension(
        filename: str, meta: dict[str, Any]
    ) -> list[Finding]:
        if not _DOUBLE_EXT_RE.search(filename):
            return []

        # Extract the final (real) extension
        parts = filename.rsplit(".", 2)
        if len(parts) < 3:
            return []

        real_ext = parts[-1].lower()
        decoy_ext = parts[-2].lower()

        if real_ext not in _DANGEROUS_EXTENSIONS:
            return []

        return [
            Finding(
                type=Category.MALWARE,
                severity=Severity.CRITICAL,
                description=(
                    f"Attachment '{filename}' uses a double extension "
                    f"('.{decoy_ext}.{real_ext}'). The visible extension '.{decoy_ext}' "
                    f"is a decoy; the actual executable extension is '.{real_ext}'. "
                    "This is a classic malware delivery technique."
                ),
                evidence={
                    "signal": "double_extension",
                    "filename": filename,
                    "decoy_extension": decoy_ext,
                    "real_extension": real_ext,
                    "size_bytes": meta.get("size_bytes"),
                },
            )
        ]

    # ------------------------------------------------------------------
    # Social-engineering lure filename check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_lure_filename(
        filename: str, meta: dict[str, Any]
    ) -> list[Finding]:
        ext = _get_extension(filename)
        keyword_match = _LURE_KEYWORDS_RE.search(filename)

        if not keyword_match:
            return []

        # Lure keyword + dangerous extension = HIGH; keyword alone = MEDIUM
        if ext in _DANGEROUS_EXTENSIONS:
            severity = Severity.HIGH
            description = (
                f"Attachment '{filename}' combines a social-engineering lure keyword "
                f"('{keyword_match.group(0)}') with a dangerous extension '.{ext}'. "
                "This pattern is commonly used in phishing and malware campaigns."
            )
        else:
            severity = Severity.MEDIUM
            description = (
                f"Attachment '{filename}' contains a social-engineering lure keyword "
                f"('{keyword_match.group(0)}'). Verify the sender before opening."
            )

        return [
            Finding(
                type=Category.SUSPICIOUS_CONTENT,
                severity=severity,
                description=description,
                evidence={
                    "signal": "lure_filename",
                    "filename": filename,
                    "matched_keyword": keyword_match.group(0),
                    "extension": ext or None,
                    "size_bytes": meta.get("size_bytes"),
                },
            )
        ]

    # ------------------------------------------------------------------
    # Suspicious size check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_suspicious_size(
        filename: str, mime_type: str, size_bytes: int, meta: dict[str, Any]
    ) -> list[Finding]:
        """Flag zero-byte attachments (often used as decoys or to test delivery)
        and unusually large attachments that may contain embedded payloads."""
        findings: list[Finding] = []

        if size_bytes == 0:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.LOW,
                    description=(
                        f"Attachment '{filename}' has a size of 0 bytes. "
                        "Zero-byte attachments may be decoys or delivery-test probes."
                    ),
                    evidence={
                        "signal": "zero_byte_attachment",
                        "filename": filename,
                        "mime_type": mime_type or None,
                        "size_bytes": 0,
                    },
                )
            )

        # Flag very large attachments (>10 MB) — unusual for transactional email
        _TEN_MB = 10 * 1024 * 1024
        if size_bytes > _TEN_MB:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.LOW,
                    description=(
                        f"Attachment '{filename}' is unusually large "
                        f"({size_bytes / (1024 * 1024):.1f} MB). "
                        "Large attachments may contain embedded payloads or archives."
                    ),
                    evidence={
                        "signal": "large_attachment",
                        "filename": filename,
                        "mime_type": mime_type or None,
                        "size_bytes": size_bytes,
                    },
                )
            )

        return findings
