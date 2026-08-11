import unittest
from unittest.mock import patch, MagicMock
from hellhound.core.ai_utils import (
    strip_thinking_tags,
    call_nvidia,
    call_ollama,
    call_openai,
    call_anthropic,
    ask_gemini,
    call_ai,
    ask_neural_core,
    load_config
)
from hellhound.core.agent import Agent, ToolSpec
from hellhound.core.tasks import Target, ScopeRules
from hellhound.core.emit import PlainEmit


class TestReasoningStripperAndLimits(unittest.TestCase):
    def test_strip_thinking_tags_basic(self):
        text = "<think>We need to check subdomains first.</think>Found 3 subdomains."
        self.assertEqual(strip_thinking_tags(text), "Found 3 subdomains.")

    def test_strip_thinking_tags_variants(self):
        text1 = "<thinking>Analyzing user input...</thinking>Target is active."
        self.assertEqual(strip_thinking_tags(text1), "Target is active.")

        text2 = "<reasoning>Let's run subfinder.</reasoning>```json\n{\"tool\": \"subfinder\"}\n```"
        self.assertEqual(strip_thinking_tags(text2), "```json\n{\"tool\": \"subfinder\"}\n```")

        text3 = "<THINK>Uppercase tag test</THINK>Clean output."
        self.assertEqual(strip_thinking_tags(text3), "Clean output.")

    def test_strip_thinking_tags_multiline_and_nested(self):
        text = """<think>
Line 1 of thought.
Line 2 of thought.
</think>
```json
{
  "tool": "httpx",
  "args": {"target": "example.com"}
}
```"""
        expected = """```json
{
  "tool": "httpx",
  "args": {"target": "example.com"}
}
```"""
        self.assertEqual(strip_thinking_tags(text), expected)

    def test_strip_thinking_tags_fallback_on_empty(self):
        text = "<think>Only thinking and nothing else</think>"
        # If stripping leaves empty string, falls back to original text
        self.assertEqual(strip_thinking_tags(text), "<think>Only thinking and nothing else</think>")

    def test_strip_unclosed_trailing_thinking(self):
        text = "Hello researcher.<think>Unfinished thoughts cut off"
        self.assertEqual(strip_thinking_tags(text), "Hello researcher.")

    @patch("requests.post")
    def test_call_nvidia_thinking_toggle_and_token_limit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "<think>private thoughts</think>Final response"}}]
        }
        mock_post.return_value = mock_resp

        res = call_nvidia("test prompt", api_key="dummy_key", thinking=False)
        self.assertEqual(res, "Final response")

        # Verify payload contains thinking=False and max_tokens=8192
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        payload = kwargs["json"]
        self.assertEqual(payload["chat_template_kwargs"], {"thinking": False})
        self.assertEqual(payload["max_tokens"], 8192)

    @patch("requests.post")
    def test_call_ollama_thinking_toggle_and_token_limit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = [
            b'{"message": {"content": "<think>Ollama reasoning</think>Live host found."}, "done": true}'
        ]
        mock_post.return_value = mock_resp

        res = call_ollama("test prompt", thinking=False)
        self.assertEqual(res, "Live host found.")

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        payload = kwargs["json"]
        self.assertEqual(payload.get("think"), False)
        self.assertEqual(payload["options"]["num_predict"], 8192)


class TestEmitWarnCalls(unittest.TestCase):
    def setUp(self):
        self.target = Target(
            name="topaz.ctfio",
            scope_rules=ScopeRules(
                in_scope=["topaz.ctfio"],
                out_scope=["forbidden.ctfio"],
                disallowed=[]
            )
        )
        self.agent = Agent(target=self.target)

    def test_scope_refusal_emits_warn(self):
        mock_emit = MagicMock()
        res = self.agent.execute_tool_call(
            tool_name="httpx",
            args={"target": "forbidden.ctfio"},
            emit=mock_emit
        )
        self.assertTrue(res.get("blocked"))
        mock_emit.warn.assert_called_once()
        warning_msg = mock_emit.warn.call_args[0][0]
        self.assertIn("SCOPE REFUSAL", warning_msg)

    def test_guard_block_emits_warn(self):
        mock_emit = MagicMock()
        # Force circuit breaker trip on the host
        for _ in range(5):
            self.agent.guard.record_failure("topaz.ctfio")

        res = self.agent.execute_tool_call(
            tool_name="httpx",
            args={"target": "topaz.ctfio", "url": "https://topaz.ctfio"},
            emit=mock_emit
        )
        self.assertTrue(res.get("blocked"))
        mock_emit.warn.assert_called_once()
        warning_msg = mock_emit.warn.call_args[0][0]
        self.assertIn("GUARD BLOCKED", warning_msg)

    def test_guard_approval_required_emits_warn(self):
        mock_emit = MagicMock()
        res = self.agent.execute_tool_call(
            tool_name="httpx",
            args={"target": "topaz.ctfio", "url": "https://topaz.ctfio", "method": "DELETE"},
            emit=mock_emit
        )
        self.assertTrue(res.get("requires_approval"))
        mock_emit.warn.assert_called_once()
        warning_msg = mock_emit.warn.call_args[0][0]
        self.assertIn("GUARD APPROVAL REQUIRED", warning_msg)


class TestSubfinderAndHallucinatedToolsAndLabels(unittest.TestCase):
    def setUp(self):
        self.target = Target(name="topaz.ctfio")
        self.agent = Agent(target=self.target)

    @patch("shutil.which", return_value=None)
    @patch("requests.get")
    def test_subfinder_no_crtsh_fallback(self, mock_get, mock_which):
        from hellhound.core.agent import _execute_subfinder
        res = _execute_subfinder({"domain": "topaz.ctfio"}, self.target, emit=None)
        # Should not make any network requests to crt.sh
        mock_get.assert_not_called()
        self.assertTrue("error" in res or res.get("count") == 0)

    @patch("hellhound.core.agent.ask_neural_core")
    def test_hallucinated_tool_does_not_leak_raw_json(self, mock_ask):
        # Step 1: Orchestrator returns a hallucinated tool name
        # Step 2: Orchestrator outputs DONE
        # Step 3: Synthesizer returns final synthesis
        mock_ask.side_effect = [
            '```json\n{"tool": "waybackurls", "args": {"target": "topaz.ctfio"}}\n```',
            'DONE',
            'Found historical endpoints for topaz.ctfio cleanly.'
        ]
        mock_emit = MagicMock()
        res = self.agent.handle_message("Enumerate endpoints for topaz.ctfio", emit=mock_emit)
        
        self.assertEqual(res, "Found historical endpoints for topaz.ctfio cleanly.")
        # Verify history received the tool error feedback
        error_entries = [h for h in self.agent.history if "[TOOL ERROR]" in h.get("content", "")]
        self.assertTrue(len(error_entries) > 0)
        self.assertIn("'waybackurls' is not a valid tool", error_entries[0]["content"])

    @patch("hellhound.core.agent.ask_neural_core")
    def test_spinner_label_transitions(self, mock_ask):
        mock_ask.return_value = 'All reconnaissance finished.'
        mock_emit = MagicMock()
        self.agent.handle_message("Status report", emit=mock_emit)
        
        # Verify set_label was called for THINKING and FINALIZING RESPONSE
        mock_emit.set_label.assert_any_call("HELLHOUND IS THINKING")
        mock_emit.set_label.assert_any_call("FINALIZING RESPONSE")

    @patch("hellhound.core.agent.ask_neural_core")
    @patch.object(Agent, "execute_tool_call")
    def test_tool_start_and_tool_result_emissions(self, mock_exec, mock_ask):
        mock_exec.return_value = {"open_ports": [80, 8080], "target": "topaz.ctfio"}
        mock_ask.side_effect = [
            '```json\n{"tool": "port_scan", "args": {"target": "topaz.ctfio"}}\n```',
            'DONE',
            'Found open ports 80 and 8080.'
        ]
        mock_emit = MagicMock()
        res = self.agent.handle_message("Scan ports on topaz.ctfio", emit=mock_emit)
        
        self.assertEqual(res, "Found open ports 80 and 8080.")
        mock_emit.tool_start.assert_called_once_with("port_scan", {"target": "topaz.ctfio"})
        mock_emit.tool_result.assert_called_once_with("port_scan", {"open_ports": [80, 8080], "target": "topaz.ctfio"})


class TestThinkingIndicatorActionTree(unittest.TestCase):
    def test_indicator_summarize_results(self):
        from hellhound.core.ai_utils import ThinkingIndicator
        indicator = ThinkingIndicator()
        
        s_port = indicator._summarize_result("port_scan", {"open_ports": [80, 443]})
        self.assertIn("Discovered 2 open port(s)", s_port)

        s_alter = indicator._summarize_result("permute_subdomains", {"permutation_count": 45})
        self.assertIn("Generated 45 candidate permutation(s)", s_alter)

        s_dnsx = indicator._summarize_result("resolve_candidates", {"resolved": ["a.com", "b.com"]})
        self.assertIn("Resolved 2 live host(s)", s_dnsx)

        s_blocked = indicator._summarize_result("httpx", {"blocked": True, "error": "Out of scope"})
        self.assertIn("Blocked", s_blocked)


if __name__ == "__main__":
    unittest.main()
