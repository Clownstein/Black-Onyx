from log_processor.templates import TemplateExtractor


def test_template_extraction_groups_similar_messages() -> None:
    extractor = TemplateExtractor()
    a = extractor.extract("Failed login for user alice from 10.0.4.21")
    b = extractor.extract("Failed login for user bob from 10.0.4.22")
    assert a.template_id
    assert "Failed login" in a.template or "<*>" in a.template or "<IP>" in a.masked_message
    assert a.cluster_id == b.cluster_id
    assert "<IP>" in a.masked_message
    assert "10.0.4.21" not in a.masked_message


def test_novel_flag_on_first_cluster_only() -> None:
    extractor = TemplateExtractor()
    first = extractor.extract("Payment authorized for order 111111")
    second = extractor.extract("Payment authorized for order 222222")
    assert first.is_novel is True
    assert second.is_novel is False
