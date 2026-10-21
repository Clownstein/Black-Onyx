from code_enrichment_worker.sarif_map import extract_cwe_ids_from_plan, map_antares_result


def test_map_json_findings():
    data = {
        "findings": [
            {
                "title": "Possible SQL injection sink",
                "file_path": "app/db.py",
                "cwe_ids": ["CWE-89"],
                "confidence": 0.8,
            }
        ],
        "summary": {"cwe_ids_triggered": ["CWE-89"]},
    }
    mapped = map_antares_result(data)
    assert mapped["cwe_ids"] == ["CWE-89"]
    assert mapped["evidence_refs"][0].startswith("antares:app/db.py")
    assert mapped["contributors"][0]["human_review_required"] is True
    assert mapped["file_hits"][0]["path"] == "app/db.py"


def test_map_sarif():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CWE-79",
                        "message": {"text": "XSS lead"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "web/view.js"}
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    mapped = map_antares_result(sarif)
    assert "CWE-79" in mapped["cwe_ids"]
    assert any("sarif:web/view.js" in r for r in mapped["evidence_refs"])


def test_extract_cwe_ids_from_plan():
    assert extract_cwe_ids_from_plan({"cwe_ids": ["CWE-22", "22"]}) == ["CWE-22"]
    assert extract_cwe_ids_from_plan({"selection": {"cwe_ids": ["CWE-78"]}}) == ["CWE-78"]
