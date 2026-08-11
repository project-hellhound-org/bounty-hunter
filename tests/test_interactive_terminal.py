import unittest
from prompt_toolkit.document import Document
from hellhound.core.commands import COMMAND_REGISTRY, handle_help
from hellhound.core.chat_ui import HellhoundCompleter, render_response_bubble
from hellhound.core.emit import PlainEmit


class TestInteractiveTerminalUI(unittest.TestCase):
    def setUp(self):
        self.completer = HellhoundCompleter()

    def test_completer_root_slash(self):
        completions = list(self.completer.get_completions(Document("/"), None))
        comp_names = [c.text for c in completions]
        self.assertIn("/recon", comp_names)
        self.assertIn("/scan", comp_names)
        self.assertIn("/hunt", comp_names)
        self.assertIn("/model", comp_names)
        self.assertIn("/scope", comp_names)
        self.assertIn("/setup", comp_names)
        self.assertIn("/report", comp_names)
        self.assertIn("/help", comp_names)

        # Confirm display_meta has description and usage
        model_c = [c for c in completions if c.text == "/model"][0]
        self.assertIn("Inspect", str(model_c.display_meta))
        self.assertIn("nvidia/nemotron-3-super-120b-a12b", str(model_c.display_meta))

    def test_completer_prefix_filter(self):
        completions = list(self.completer.get_completions(Document("/mo"), None))
        self.assertEqual(len(completions), 1)
        self.assertEqual(completions[0].text, "/model")

    def test_completer_model_subcommands(self):
        completions = list(self.completer.get_completions(Document("/model "), None))
        texts = [c.text for c in completions]
        self.assertIn("set-key", texts)
        self.assertIn("nvidia/nemotron-3-super-120b-a12b", texts)
        self.assertIn("--session-only", texts)

    def test_completer_setup_subcommands(self):
        completions = list(self.completer.get_completions(Document("/setup "), None))
        texts = [c.text for c in completions]
        self.assertIn("tools auto-install on", texts)
        self.assertIn("tools install-all", texts)

    def test_command_categories_and_help(self):
        for name, cmd in COMMAND_REGISTRY.items():
            if name.startswith("/"):
                self.assertIn(cmd.category, ["hunting", "config", "session", "general"])

        res = handle_help([], {}, PlainEmit())
        self.assertEqual(res["status"], "success")
        self.assertTrue(len(res["commands"]) >= 10)

    def test_render_response_bubble_no_crash(self):
        # Multi-line text with HTML special characters and markdown
        sample = "Line 1 <script>alert(1)</script>\n\nLine 2 with & and <b>test</b>\n- List item 1"
        try:
            render_response_bubble(sample, sender="TEST_SENDER")
        except Exception as e:
            self.fail(f"render_response_bubble raised an exception: {e}")


if __name__ == "__main__":
    unittest.main()
