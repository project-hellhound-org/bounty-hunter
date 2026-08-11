import unittest
import json
import os
from unittest.mock import patch, MagicMock
from hellhound.core.agent import Agent, ScopeRules, Target
from hellhound.core.ai_utils import load_config, ask_neural_core
from hellhound.core.commands import handle_model
from hellhound.core.emit import PlainEmit
from click.testing import CliRunner
from hellhound.cli import cli


class TestTwoTierRouting(unittest.TestCase):
    def setUp(self):
        self.emit = PlainEmit()
        self.session_context = {"options": {}}

    @patch("hellhound.core.ai_utils.call_ai")
    @patch("hellhound.core.ai_utils.load_config")
    def test_role_based_provider_and_model_resolution(self, mock_load, mock_call):
        mock_load.return_value = {
            "ai_provider": "ollama",
            "ai_model": "qwen2.5:3b-instruct",
            "orchestrator_provider": "ollama",
            "orchestrator_model": "qwen2.5:3b-instruct",
            "synthesizer_provider": "nvidia",
            "synthesizer_model": "nvidia/nemotron-3-super-120b-a12b",
            "api_keys": {"nvidia": "nvapi-testkey-12345"},
            "api_key": "ollama"
        }
        mock_call.return_value = "Mocked Response"

        # 1. Orchestrator call
        ask_neural_core("test prompt", role="orchestrator", thinking=False)
        mock_call.assert_called_with(
            "test prompt",
            provider="ollama",
            api_key="ollama",
            model="qwen2.5:3b-instruct",
            timeout=300,
            system_prompt=None,
            history=None,
            thinking=False,
            max_tokens=None
        )

        # 2. Synthesizer call
        ask_neural_core("test prompt", role="synthesizer", thinking=True)
        mock_call.assert_called_with(
            "test prompt",
            provider="nvidia",
            api_key="nvapi-testkey-12345",
            model="nvidia/nemotron-3-super-120b-a12b",
            timeout=300,
            system_prompt=None,
            history=None,
            thinking=True,
            max_tokens=None
        )

    @patch("hellhound.core.ai_utils.call_ai")
    @patch("hellhound.core.ai_utils.load_config")
    def test_cloud_to_local_fallback_without_api_key(self, mock_load, mock_call):
        mock_load.return_value = {
            "orchestrator_provider": "ollama",
            "orchestrator_model": "qwen2.5:3b-instruct",
            "synthesizer_provider": "nvidia",
            "synthesizer_model": "nvidia/nemotron-3-super-120b-a12b",
            "api_keys": {},
            "api_key": "ollama"
        }
        mock_call.return_value = "Fallback Response"

        ask_neural_core("synthesizer prompt", role="synthesizer", thinking=True)
        # Should gracefully fall back to local orchestrator provider/model
        mock_call.assert_called_with(
            "synthesizer prompt",
            provider="ollama",
            api_key="ollama",
            model="qwen2.5:3b-instruct",
            timeout=300,
            system_prompt=None,
            history=None,
            thinking=True,
            max_tokens=None
        )

    @patch("hellhound.core.agent.ask_neural_core")
    def test_agent_orchestrator_loop_and_single_synthesizer_call(self, mock_ask):
        target = Target(name="example.com", scope_rules=ScopeRules(in_scope=["example.com"], out_scope=[], disallowed=[]))
        agent = Agent(target=target)
        mock_emit = MagicMock()

        # Call 1 (Orch): return tool call
        # Call 2 (Orch): return DONE
        # Call 3 (Synth): return final synthesis
        mock_ask.side_effect = [
            '```json\n{"tool": "port_scan", "args": {"target": "example.com"}}\n```',
            'DONE',
            'Deep synthesized security analysis with open ports findings.'
        ]

        with patch.object(agent, "execute_tool_call", return_value={"open_ports": [80, 443]}):
            res = agent.handle_message("Scan example.com", emit=mock_emit)

        self.assertIn("Deep synthesized security analysis", res)
        self.assertEqual(mock_ask.call_count, 3)

        # Check call arguments
        call1_kwargs = mock_ask.call_args_list[0].kwargs
        self.assertEqual(call1_kwargs.get("role"), "orchestrator")
        self.assertFalse(call1_kwargs.get("thinking"))
        self.assertIn("HELLHOUND Orchestrator", call1_kwargs.get("system_prompt"))

        call2_kwargs = mock_ask.call_args_list[1].kwargs
        self.assertEqual(call2_kwargs.get("role"), "orchestrator")
        self.assertFalse(call2_kwargs.get("thinking"))

        call3_kwargs = mock_ask.call_args_list[2].kwargs
        self.assertEqual(call3_kwargs.get("role"), "synthesizer")
        self.assertTrue(call3_kwargs.get("thinking"))
        self.assertIn("ALWAYS-ON BASELINE DOCTRINE", call3_kwargs.get("system_prompt"))

    @patch("hellhound.core.commands.save_config")
    @patch("hellhound.core.commands.load_config")
    def test_model_command_role_switching(self, mock_load, mock_save):
        mock_load.return_value = {
            "orchestrator_provider": "ollama",
            "orchestrator_model": "qwen2.5:3b-instruct",
            "synthesizer_provider": "nvidia",
            "synthesizer_model": "nvidia/nemotron-3-super-120b-a12b",
            "api_keys": {"nvidia": "key123", "anthropic": "key456"}
        }

        # 1. Switch orchestrator
        res_orch = handle_model(["orchestrator", "ollama", "mistral:7b"], self.session_context, self.emit)
        self.assertEqual(res_orch["status"], "success")
        self.assertEqual(res_orch["role"], "orchestrator")
        self.assertEqual(res_orch["model"], "mistral:7b")
        self.assertEqual(self.session_context["options"]["orchestrator_model"], "mistral:7b")

        # 2. Switch synthesizer
        res_synth = handle_model(["synthesizer", "claude-3-5-sonnet"], self.session_context, self.emit)
        self.assertEqual(res_synth["status"], "success")
        self.assertEqual(res_synth["role"], "synthesizer")
        self.assertEqual(res_synth["model"], "claude-3-5-sonnet")
        self.assertEqual(res_synth["provider"], "anthropic")
        self.assertEqual(self.session_context["options"]["synthesizer_model"], "claude-3-5-sonnet")

    def test_cli_help_text_and_hidden_classic_flag(self):
        runner = CliRunner()
        res = runner.invoke(cli, ["--help"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Autonomous bug bounty recon & triage assistant", res.output)
        self.assertIn("/scope show --json", res.output)
        self.assertNotIn("/howl", res.output)
        self.assertNotIn("--classic", res.output)


if __name__ == "__main__":
    unittest.main()
