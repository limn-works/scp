"""Tests for client-side ContentPath, MimeType, and deploy_id validation (SCP-297).

Validates that the SDK-layer validation functions produce clear, descriptive
error messages for invalid inputs BEFORE the FFI boundary is crossed.

Mirrors the Rust validation in ``crates/scp-core/src/context/broadcast_content.rs``.
"""

from __future__ import annotations

import pytest

from scp_sdk.context import (
    validate_content_path,
    validate_deploy_id,
    validate_mime_type,
)
from scp_sdk.errors import ValidationError

# ---------------------------------------------------------------------------
# ContentPath validation
# ---------------------------------------------------------------------------


class TestValidateContentPath:
    """Tests for validate_content_path (SCP-297)."""

    def test_valid_root(self) -> None:
        assert validate_content_path("/") is None

    def test_valid_simple_path(self) -> None:
        assert validate_content_path("/index.html") is None

    def test_valid_nested_path(self) -> None:
        assert validate_content_path("/assets/css/main.css") is None

    def test_valid_hidden_file(self) -> None:
        assert validate_content_path("/.well-known/acme-challenge/token") is None

    def test_rejects_no_leading_slash(self) -> None:
        with pytest.raises(ValidationError, match="must start with '/'"):
            validate_content_path("index.html")

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValidationError, match="must start with '/'"):
            validate_content_path("")

    def test_rejects_too_long(self) -> None:
        with pytest.raises(ValidationError, match="exceeds 1024 bytes"):
            validate_content_path("/" + "a" * 1024)

    def test_rejects_backslash(self) -> None:
        with pytest.raises(ValidationError, match="backslashes"):
            validate_content_path("/path\\file")

    def test_rejects_percent_encoded(self) -> None:
        with pytest.raises(ValidationError, match="percent-encoded"):
            validate_content_path("/path%20file")

    def test_rejects_query_string(self) -> None:
        with pytest.raises(ValidationError, match="query strings"):
            validate_content_path("/path?key=value")

    def test_rejects_fragment(self) -> None:
        with pytest.raises(ValidationError, match="fragments"):
            validate_content_path("/path#section")

    def test_rejects_null_byte(self) -> None:
        with pytest.raises(ValidationError, match="null bytes"):
            validate_content_path("/path\x00file")

    def test_rejects_control_char(self) -> None:
        with pytest.raises(ValidationError, match="control character"):
            validate_content_path("/path\x01file")

    def test_rejects_del_char(self) -> None:
        with pytest.raises(ValidationError, match="control character U\\+007F"):
            validate_content_path("/path\x7ffile")

    def test_rejects_double_slash(self) -> None:
        with pytest.raises(ValidationError, match="'//'"):
            validate_content_path("/path//file")

    def test_rejects_trailing_slash(self) -> None:
        with pytest.raises(ValidationError, match="trailing slash"):
            validate_content_path("/path/")

    def test_rejects_dot_segment(self) -> None:
        with pytest.raises(ValidationError, match="'\\.' segments"):
            validate_content_path("/path/./file")

    def test_rejects_dotdot_segment(self) -> None:
        with pytest.raises(ValidationError, match="directory traversal"):
            validate_content_path("/path/../etc/passwd")

    def test_rejects_c1_control_char(self) -> None:
        """Fix 4: C1 control range U+0080-U+009F."""
        with pytest.raises(ValidationError, match="control character U\\+0085"):
            validate_content_path("/path\u0085file")

    def test_rejects_zero_width_space(self) -> None:
        """Fix 1: Zero-width space U+200B."""
        with pytest.raises(ValidationError, match="whitespace/formatting U\\+200B"):
            validate_content_path("/path\u200bfile")

    def test_rejects_bidi_override(self) -> None:
        """Fix 1: Bidi override U+202E."""
        with pytest.raises(ValidationError, match="whitespace/formatting U\\+202E"):
            validate_content_path("/path\u202efile")

    def test_rejects_nbsp(self) -> None:
        """Fix 1: Non-breaking space U+00A0."""
        with pytest.raises(ValidationError, match="whitespace/formatting U\\+00A0"):
            validate_content_path("/path\u00a0file")

    def test_nfc_normalization(self) -> None:
        """Fix 3: NFC normalization — decomposed e-acute accepted after normalization."""
        # U+0065 U+0301 (e + combining acute) normalizes to U+00E9 (e-acute)
        assert validate_content_path("/caf\u0065\u0301") is None

    def test_error_code(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            validate_content_path("no-slash")
        assert exc_info.value.code == "SCP-VALID-7010"


# ---------------------------------------------------------------------------
# MimeType validation
# ---------------------------------------------------------------------------


class TestValidateMimeType:
    """Tests for validate_mime_type (SCP-297)."""

    def test_valid_text_html(self) -> None:
        assert validate_mime_type("text/html") is None

    def test_valid_application_json(self) -> None:
        assert validate_mime_type("application/json") is None

    def test_valid_image_png(self) -> None:
        assert validate_mime_type("image/png") is None

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_mime_type("")

    def test_rejects_no_slash(self) -> None:
        with pytest.raises(ValidationError, match="exactly one '/'"):
            validate_mime_type("texthtml")

    def test_rejects_double_slash(self) -> None:
        with pytest.raises(ValidationError, match="exactly one '/'"):
            validate_mime_type("text/html/extra")

    def test_rejects_empty_type(self) -> None:
        with pytest.raises(ValidationError, match="both be non-empty"):
            validate_mime_type("/html")

    def test_rejects_empty_subtype(self) -> None:
        with pytest.raises(ValidationError, match="both be non-empty"):
            validate_mime_type("text/")

    def test_rejects_semicolon(self) -> None:
        with pytest.raises(ValidationError, match="parameters"):
            validate_mime_type("text/html; charset=utf-8")

    def test_rejects_cr(self) -> None:
        with pytest.raises(ValidationError, match="control character"):
            validate_mime_type("text/html\r")

    def test_rejects_lf(self) -> None:
        with pytest.raises(ValidationError, match="control character"):
            validate_mime_type("text/html\n")

    def test_rejects_null(self) -> None:
        with pytest.raises(ValidationError, match="control character"):
            validate_mime_type("text/\x00html")

    def test_rejects_c1_control_char(self) -> None:
        """Fix 4: C1 control range U+0080-U+009F in MIME type."""
        with pytest.raises(ValidationError, match="control character U\\+0085"):
            validate_mime_type("text/\u0085html")

    def test_rejects_non_tchar_in_type(self) -> None:
        """Fix 2: Non-tchar character in type part."""
        with pytest.raises(ValidationError, match="type part contains invalid"):
            validate_mime_type("te xt/html")

    def test_rejects_non_tchar_in_subtype(self) -> None:
        """Fix 2: Non-tchar character in subtype part."""
        with pytest.raises(ValidationError, match="subtype part contains invalid"):
            validate_mime_type("text/ht ml")

    def test_accepts_tchar_special_chars(self) -> None:
        """Fix 2: tchar special characters are accepted."""
        assert validate_mime_type("application/vnd.foo+bar") is None

    def test_error_code(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            validate_mime_type("")
        assert exc_info.value.code == "SCP-VALID-7011"


# ---------------------------------------------------------------------------
# deploy_id validation
# ---------------------------------------------------------------------------


class TestValidateDeployId:
    """Tests for validate_deploy_id (SCP-297)."""

    def test_valid_simple(self) -> None:
        assert validate_deploy_id("deploy-1") is None

    def test_valid_hex(self) -> None:
        assert validate_deploy_id("abc123def456") is None

    def test_valid_underscore(self) -> None:
        assert validate_deploy_id("my_deploy_id") is None

    def test_valid_mixed(self) -> None:
        assert validate_deploy_id("Deploy-2024_v1") is None

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_deploy_id("")

    def test_rejects_too_long(self) -> None:
        with pytest.raises(ValidationError, match="exceeds 128 bytes"):
            validate_deploy_id("a" * 129)

    def test_rejects_spaces(self) -> None:
        with pytest.raises(ValidationError, match="ASCII alphanumeric"):
            validate_deploy_id("deploy 1")

    def test_rejects_special_chars(self) -> None:
        with pytest.raises(ValidationError, match="ASCII alphanumeric"):
            validate_deploy_id("deploy@1")

    def test_rejects_slash(self) -> None:
        with pytest.raises(ValidationError, match="ASCII alphanumeric"):
            validate_deploy_id("deploy/1")

    def test_rejects_unicode(self) -> None:
        with pytest.raises(ValidationError, match="ASCII alphanumeric"):
            validate_deploy_id("deploy\u00e9")

    def test_error_code(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            validate_deploy_id("")
        assert exc_info.value.code == "SCP-VALID-7012"
