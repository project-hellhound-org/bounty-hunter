"""
tests/test_ctf_lab_recon.py

Unit tests for CTF / Lab reconnaissance skill discovery,
context detection, prompt injection, and automatic scoping.
"""

import unittest
from unittest.mock import patch, MagicMock

from hellhound.core.tasks import Target, ScopeRules
from hellhound.core.agent import Agent
from hellhound.core.skills import (
    discover_skills,
    is_ctf_lab_context,
    is_ctf_domain_pattern,
    is_ctf_auto_scope_eligible,
    get_relevant_skills_prompt,
    search_skills,
    load_skill_body
)


class TestCtfLabReconSkill(unittest.TestCase):
    def test_skill_discovery(self):
        skills = discover_skills()
        self.assertIn("ctf-lab-recon", skills)
        skill = skills["ctf-lab-recon"]
        self.assertEqual(skill.name, "ctf-lab-recon")
        self.assertIn("CTF", skill.description)
        self.assertIn("HTB", skill.description)
        self.assertIn("THM", skill.description)

        body = load_skill_body("ctf-lab-recon")
        self.assertIn("PASSIVE RECON FAILURE MODE", body)
        self.assertIn("dns_bruteforce", body)
        self.assertIn("vhost_fuzz", body)
        self.assertIn("TRIVIAL SCOPE DOCTRINE", body)

    def test_is_ctf_domain_pattern(self):
        self.assertTrue(is_ctf_domain_pattern("topaz.ctfio.com"))
        self.assertTrue(is_ctf_domain_pattern("indium.ctfio.com"))
        self.assertTrue(is_ctf_domain_pattern("machine.htb"))
        self.assertTrue(is_ctf_domain_pattern("target.tryhackme.com"))
        self.assertTrue(is_ctf_domain_pattern("box.vulnhub.com"))
        self.assertTrue(is_ctf_domain_pattern("ctf.example.org"))
        self.assertTrue(is_ctf_domain_pattern("localhost"))
        self.assertTrue(is_ctf_domain_pattern("127.0.0.1"))
        self.assertTrue(is_ctf_domain_pattern("192.168.1.100"))

        self.assertFalse(is_ctf_domain_pattern("discover.com"))
        self.assertFalse(is_ctf_domain_pattern("example.com"))
        self.assertFalse(is_ctf_domain_pattern("hackerone.com"))
        self.assertFalse(is_ctf_domain_pattern("google.com"))

    def test_is_ctf_auto_scope_eligible(self):
        # Real targets without CTF pattern or explicit isolation phrases
        self.assertFalse(is_ctf_auto_scope_eligible("discover.com", "recon discover.com"))
        self.assertFalse(is_ctf_auto_scope_eligible("discover.com", "let's test my approach in a lab environment for discover.com"))
        self.assertFalse(is_ctf_auto_scope_eligible("example.com", "scan example.com"))

        # Genuine CTF domain patterns
        self.assertTrue(is_ctf_auto_scope_eligible("indium.ctfio.com", "recon indium.ctfio.com"))
        self.assertTrue(is_ctf_auto_scope_eligible("topaz.ctfio.com", "find subdomains"))
        self.assertTrue(is_ctf_auto_scope_eligible("machine.htb", "recon"))

        # Explicit multi-word isolation authorization phrases
        self.assertTrue(is_ctf_auto_scope_eligible("target.internal", "this is a training range, recon target.internal"))
        self.assertTrue(is_ctf_auto_scope_eligible("target.org", "check this isolated target"))

    def test_is_ctf_lab_context_detector(self):
        # Positive matches
        self.assertTrue(is_ctf_lab_context("find subdomains for topaz.ctfio.com, it's a CTF target"))
        self.assertTrue(is_ctf_lab_context("this is a CTF lab, find subdomains"))
        self.assertTrue(is_ctf_lab_context("HTB machine, need active recon"))
        self.assertTrue(is_ctf_lab_context("Enumerate this tryhackme box"))
        self.assertTrue(is_ctf_lab_context("vulnhub machine scan"))
        self.assertTrue(is_ctf_lab_context("training range active enumeration"))
        self.assertTrue(is_ctf_lab_context("check this isolated target"))

        # Negative matches (regular bug bounty)
        self.assertFalse(is_ctf_lab_context("recon example.com for our engagement"))
        self.assertFalse(is_ctf_lab_context("find endpoints on hackerone.com"))
        self.assertFalse(is_ctf_lab_context("what is the scope of google.com"))
        self.assertFalse(is_ctf_lab_context("hello, how does IDOR work?"))

    def test_get_relevant_skills_prompt_ctf_selection(self):
        # CTF query on session start should inject ctf-lab-recon
        prompt = get_relevant_skills_prompt("this is a CTF lab, find subdomains", history_len=0)
        self.assertIn("### ctf-lab-recon", prompt)
        self.assertIn("PASSIVE RECON FAILURE MODE", prompt)

        # HTB query should also select ctf-lab-recon
        prompt_htb = get_relevant_skills_prompt("HTB machine, need active recon", history_len=0)
        self.assertIn("### ctf-lab-recon", prompt_htb)

        # Standard bug bounty query on session start should select bb-methodology instead
        prompt_bb = get_relevant_skills_prompt("recon example.com for our engagement", history_len=0)
        self.assertIn("### bb-methodology", prompt_bb)
        self.assertNotIn("### ctf-lab-recon", prompt_bb)

    @patch("hellhound.core.agent.ask_neural_core")
    def test_auto_scope_shortcut_on_ctf_context(self, mock_ask):
        mock_ask.return_value = "Starting active DNS brute-force against topaz.ctfio.com"
        target = Target(name="default", scope_rules=ScopeRules(in_scope=[], out_scope=[], disallowed=[]))
        agent = Agent(target=target)

        mock_emit = MagicMock()
        user_msg = "find subdomains for topaz.ctfio.com, it's a CTF target"
        res = agent.handle_message(user_msg, emit=mock_emit)

        # Confirm target switched to topaz.ctfio.com
        self.assertEqual(agent.target.name, "topaz.ctfio.com")
        # Confirm auto-scoping populated in_scope without manual /scope command
        self.assertIn("*.topaz.ctfio.com", agent.target.scope_rules.in_scope)
        self.assertIn("topaz.ctfio.com", agent.target.scope_rules.in_scope)

        # Confirm emit was notified of CTF auto-scoping
        mock_emit.info.assert_any_call(
            "[*] CTF/lab context detected — auto-scoping to topaz.ctfio.com (no manual /scope needed for lab targets)"
        )

    def test_scope_refusal_on_unscoped_real_target(self):
        target = Target(name="default", scope_rules=ScopeRules(in_scope=[], out_scope=[], disallowed=[]))
        agent = Agent(target=target)
        mock_emit = MagicMock()

        # 1. Bare recon request against unscoped domain
        res1 = agent.handle_message("recon discover.com", emit=mock_emit)
        self.assertEqual(agent.target.name, "discover.com")
        self.assertEqual(agent.target.scope_rules.in_scope, [])
        self.assertIn("No authorized scope is defined for 'discover.com'", res1)
        self.assertIn("I won't start reconnaissance without it", res1)

        # 2. Recon request with 'lab' in query against regular public domain
        agent2 = Agent(target=Target(name="default", scope_rules=ScopeRules(in_scope=[], out_scope=[], disallowed=[])))
        res2 = agent2.handle_message("let's test my approach in a lab environment for discover.com", emit=mock_emit)
        self.assertEqual(agent2.target.name, "discover.com")
        self.assertEqual(agent2.target.scope_rules.in_scope, [])
        self.assertIn("No authorized scope is defined for 'discover.com'", res2)
        self.assertIn("I won't start reconnaissance without it", res2)

    @patch("hellhound.core.agent.ask_neural_core")
    def test_normal_bug_bounty_does_not_auto_scope_with_ctf_message(self, mock_ask):
        mock_ask.return_value = "Proceeding with standard engagement recon"
        target = Target(name="default", scope_rules=ScopeRules(in_scope=[], out_scope=[], disallowed=[]))
        agent = Agent(target=target)

        mock_emit = MagicMock()
        # Message with domain but NO CTF context
        user_msg = "recon unscoped-bounty-corp.com for our engagement"
        res = agent.handle_message(user_msg, emit=mock_emit)

        # Target name updated from domain match
        self.assertEqual(agent.target.name, "unscoped-bounty-corp.com")
        # CTF auto-scoping emit notification should NOT have been called
        for call_args in mock_emit.info.call_args_list:
            self.assertNotIn("CTF/lab context detected", call_args[0][0])
        # Returns scope refusal message
        self.assertIn("No authorized scope is defined for 'unscoped-bounty-corp.com'", res)


if __name__ == "__main__":
    unittest.main()
