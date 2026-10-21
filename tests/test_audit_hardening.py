"""Focused regressions for bounded external input added by the security audit."""

from __future__ import annotations

import zipfile

import pytest
from pydantic import ValidationError

from black_onyx.api.schemas import IocTransformList, TaxiiPublishRequest, WebhookEventRequest
from black_onyx.extraction.text import _extract_openxml


def test_webhook_structured_iocs_are_bounded() -> None:
    with pytest.raises(ValidationError, match="at most 500"):
        WebhookEventRequest(iocs={"domains": [f"host-{i}.example" for i in range(501)]})
    with pytest.raises(ValidationError, match="4096"):
        WebhookEventRequest(iocs={"domains": ["x" * 4097]})


def test_taxii_objects_are_bounded() -> None:
    with pytest.raises(ValidationError):
        TaxiiPublishRequest(collection_id="collection", objects=[{} for _ in range(501)])


def test_ioc_transform_list_is_bounded() -> None:
    with pytest.raises(ValidationError):
        IocTransformList.model_validate([])
    with pytest.raises(ValidationError):
        IocTransformList.model_validate(["x"] * 501)
    with pytest.raises(ValidationError):
        IocTransformList.model_validate(["y" * 4097])
    ok = IocTransformList.model_validate(["evil.example", "1.2.3.4"])
    assert ok.root == ["evil.example", "1.2.3.4"]


def test_openxml_extraction_rejects_unsafe_compression_ratio(tmp_path) -> None:
    archive = tmp_path / "bomb.docx"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("word/document.xml", "<root>" + ("A" * 4_000_000) + "</root>")
    with pytest.raises(ValueError, match="compression ratio"):
        _extract_openxml(str(archive))
