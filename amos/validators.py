"""
amos/validators.py — File upload validators for avatar and document uploads.

Security controls applied at upload time
-----------------------------------------
1. File size limit: prevents resource exhaustion / storage abuse.
2. Extension whitelist: blocks executables and other dangerous types by name.
3. Magic-byte check: reads the first bytes of the actual file content so a
   PHP shell renamed to .jpg or a Windows PE renamed to .pdf is rejected
   even if the extension looks safe.  Never trust client-supplied metadata alone.

What is never allowed
----------------------
- Server-side executable extensions (.php, .py, .sh, .exe, .bat, …)
- Any MIME type or content signature that does not match the declared extension
- Files larger than the per-type size limit

Docs:
  OWASP File Upload Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
"""

import os

from django.core.exceptions import ValidationError

# ---------------------------------------------------------------------------
# Size limits
# ---------------------------------------------------------------------------

AVATAR_MAX_BYTES = 2 * 1024 * 1024   # 2 MB
DOCUMENT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB

# ---------------------------------------------------------------------------
# Allowed extensions (lower-case, with leading dot)
# ---------------------------------------------------------------------------

AVATAR_ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
DOCUMENT_ALLOWED_EXTENSIONS = {".pdf", ".txt"}

# ---------------------------------------------------------------------------
# Magic-byte signatures
# Read only the first 12 bytes — enough to identify all supported types.
# ---------------------------------------------------------------------------

_JPEG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC  = b"\x89PNG\r\n\x1a\n"
_GIF87_MAGIC = b"GIF87a"
_GIF89_MAGIC = b"GIF89a"
_WEBP_RIFF   = b"RIFF"     # bytes 0-3
_WEBP_MARK   = b"WEBP"     # bytes 8-11
_PDF_MAGIC   = b"%PDF"


def _sniff_type(upload):
    """
    Read the first 12 bytes of *upload* and return a short identifier string:

      'jpeg' | 'png' | 'gif' | 'webp' | 'pdf' | None

    The file position is reset to 0 afterwards so subsequent reads are unaffected.
    Raises nothing — callers should treat None as unrecognised.
    """
    header = upload.read(12)
    upload.seek(0)

    # WebP: RIFF????WEBP
    if header[:4] == _WEBP_RIFF and header[8:12] == _WEBP_MARK:
        return "webp"

    if header[:3] == _JPEG_MAGIC:
        return "jpeg"
    if header[:8] == _PNG_MAGIC:
        return "png"
    if header[:6] in (_GIF87_MAGIC, _GIF89_MAGIC):
        return "gif"
    if header[:4] == _PDF_MAGIC:
        return "pdf"

    return None


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_avatar(upload):
    """
    Validate an avatar upload file.

    Checks (in order):
      1. Size  ≤ AVATAR_MAX_BYTES
      2. Extension is in AVATAR_ALLOWED_EXTENSIONS
      3. File content matches an image magic signature

    Raises ValidationError on any failure.
    """
    # 1. Size — checked first so we do not read large files unnecessarily.
    if upload.size > AVATAR_MAX_BYTES:
        limit_mb = AVATAR_MAX_BYTES // (1024 * 1024)
        actual_mb = upload.size / (1024 * 1024)
        raise ValidationError(
            f"Avatar must be {limit_mb} MB or smaller "
            f"(uploaded file is {actual_mb:.1f} MB)."
        )

    # 2. Extension whitelist.
    ext = os.path.splitext(upload.name)[1].lower()
    if ext not in AVATAR_ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(AVATAR_ALLOWED_EXTENSIONS))
        raise ValidationError(
            f"Avatar extension '{ext or '(none)'}' is not allowed. "
            f"Accepted: {allowed}."
        )

    # 3. Magic-byte check — detects extension spoofing.
    detected = _sniff_type(upload)
    if detected not in ("jpeg", "png", "gif", "webp"):
        raise ValidationError(
            "File content does not match a recognised image format. "
            "Upload a real JPEG, PNG, GIF, or WebP file."
        )


def validate_document(upload):
    """
    Validate a document upload file.

    Checks (in order):
      1. Size  ≤ DOCUMENT_MAX_BYTES
      2. Extension is in DOCUMENT_ALLOWED_EXTENSIONS
      3. PDF files must start with the PDF magic bytes (prevents spoofing)

    Plain-text (.txt) files have no universal magic signature, so only
    extension and size are checked for that type.

    Raises ValidationError on any failure.
    """
    # 1. Size.
    if upload.size > DOCUMENT_MAX_BYTES:
        limit_mb = DOCUMENT_MAX_BYTES // (1024 * 1024)
        actual_mb = upload.size / (1024 * 1024)
        raise ValidationError(
            f"Document must be {limit_mb} MB or smaller "
            f"(uploaded file is {actual_mb:.1f} MB)."
        )

    # 2. Extension whitelist.
    ext = os.path.splitext(upload.name)[1].lower()
    if ext not in DOCUMENT_ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(DOCUMENT_ALLOWED_EXTENSIONS))
        raise ValidationError(
            f"Document extension '{ext or '(none)'}' is not allowed. "
            f"Accepted: {allowed}."
        )

    # 3. Magic-byte check for PDF — plain text has no signature.
    if ext == ".pdf":
        detected = _sniff_type(upload)
        if detected != "pdf":
            raise ValidationError(
                "File has a .pdf extension but does not contain a valid PDF "
                "signature. Upload a real PDF file."
            )
