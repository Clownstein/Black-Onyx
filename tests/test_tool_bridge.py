"""Tests for Gemma 4 tool bridge helpers."""

from black_onyx.llm.tool_bridge import (
    effective_system_prompt,
    format_gemma_tool_response,
    gemma_tool_to_json_protocol,
    openai_tool_call_to_gemma,
    parse_gemma_tool_call,
    parse_gemma_tool_calls,
    parse_tool_turn,
    strip_gemma_control_blocks,
)


class TestStripGemmaControlBlocks:
    def test_strips_thought_channel(self):
        text = "Answer here<|channel>thought internal reasoning<channel|> tail"
        assert strip_gemma_control_blocks(text) == "Answer here tail"

    def test_strips_tool_call_blocks(self):
        raw = '<|tool_call>call:web_search{query:<|"|>CVE-2024<|"|>}<tool_call|>'
        assert strip_gemma_control_blocks(raw) == ""


class TestParseGemmaToolCalls:
    def test_parse_web_search(self):
        block = 'call:web_search{query:<|"|>Emotet IOCs<|"|>}'
        parsed = parse_gemma_tool_call(block)
        assert parsed is not None
        assert parsed.name == "web_search"
        assert parsed.arguments["query"] == "Emotet IOCs"

    def test_parse_multiple_calls(self):
        text = (
            '<|tool_call>call:web_search{query:<|"|>alpha<|"|>}<tool_call|>'
            '<|tool_call>call:scrape_url{url:<|"|>https://example.com<|"|>}<tool_call|>'
        )
        calls = parse_gemma_tool_calls(text)
        assert len(calls) == 2
        assert calls[0].name == "web_search"
        assert calls[1].name == "scrape_url"

    def test_maps_to_json_protocol(self):
        call = parse_gemma_tool_call('call:web_search{query:<|"|>test<|"|>}')
        assert call is not None
        payload = gemma_tool_to_json_protocol(call)
        assert payload == {"tool": "web_search", "args": {"query": "test"}}


class TestOpenAIToGemma:
    def test_round_trip_shape(self):
        gemma = openai_tool_call_to_gemma(
            "black_onyx_evidence_search",
            {"query": "lateral movement", "limit": 5},
            call_id="call_evidence_1",
        )
        assert gemma.startswith("<|tool_call>call:black_onyx_evidence_search{")
        assert '<|"|>lateral movement<|"|>' in gemma
        assert gemma.endswith("<tool_call|>")


class TestFormatToolResponse:
    def test_wraps_content(self):
        out = format_gemma_tool_response("web_search", '{"hits":1}', call_id="call_1")
        assert out.startswith("<|tool_response>call:call_1{")
        assert out.endswith("<tool_response|>")


class TestEffectiveSystemPrompt:
    def test_low_thinking_appended_for_openai_compatible(self):
        class Compat:
            thinking_level = "LOW"

        class LLM:
            openai_compatible = Compat()

        prompt = effective_system_prompt("Base prompt.", LLM(), "openai_compatible")
        assert "Base prompt." in prompt
        assert "LOW thinking" in prompt

    def test_other_providers_unchanged(self):
        class LLM:
            openai_compatible = type("C", (), {"thinking_level": "LOW"})()

        assert effective_system_prompt("Base.", LLM(), "local") == "Base."

    def test_investigation_purpose_appended(self):
        class LLM:
            pass

        prompt = effective_system_prompt("Base.", LLM(), "local", purpose="investigation")
        assert "Base." in prompt
        assert "suggest-only" in prompt.lower()
        assert "containment" in prompt.lower()


class TestParseToolTurn:
    def test_final_answer_without_tools(self):
        turn = parse_tool_turn("Here is the analyst summary.")
        assert turn.final_answer == "Here is the analyst summary."
        assert turn.tool_calls == []


class TestGemmaToolDeclarations:
    def test_openai_tools_to_gemma_declarations(self):
        from black_onyx.llm.tool_bridge import openai_tools_to_gemma_declarations

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "black_onyx_evidence_search",
                    "description": "Semantic evidence search",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string", "description": "search text"}},
                        "required": ["query"],
                    },
                },
            }
        ]
        text = openai_tools_to_gemma_declarations(tools)
        assert text.startswith("<|tool>black_onyx_evidence_search{")
        assert "Semantic evidence search" in text
        assert "query:{" in text
        assert text.endswith("<tool|>")
