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
        validate_content_path("/")

    def test_valid_simple_path(self) -> None:
        validate_content_path("/index.html")

    def test_valid_nested_path(self) -> None:
        validate_content_path("/assets/css/main.css")

    def test_valid_hidden_file(self) -> None:
        validate_content_path("/.well-known/acme-challenge/token")

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
        validate_mime_type("text/html")

    def test_valid_application_json(self) -> None:
        validate_mime_type("application/json")

    def test_valid_image_png(self) -> None:
        validate_mime_type("image/png")

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
        validate_deploy_id("deploy-1")

    def test_valid_hex(self) -> None:
        validate_deploy_id("abc123def456")

    def test_valid_underscore(self) -> None:
        validate_deploy_id("my_deploy_id")

    def test_valid_mixed(self) -> None:
        validate_deploy_id("Deploy-2024_v1")

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
