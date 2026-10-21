import html


def test_log_and_code_content_escaped_for_ui():
    malicious_log = '<script>alert("xss")</script> Failed login'
    malicious_code = 'print("</script><script>alert(1)</script>")'
    escaped_log = html.escape(malicious_log)
    escaped_code = html.escape(malicious_code)
    assert "<script>" not in escaped_log
    assert "&lt;script&gt;" in escaped_log
    assert "<script>" not in escaped_code
