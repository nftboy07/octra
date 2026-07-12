"""GitHub-lexicon hunter tests (stdlib-only, tiny corpus)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from octra_recon.github_lexicon import (
    extract_corpus,
    run_github_lexicon,
    _generate_candidates,
    _load_bip39_set,
)
from octra_recon.wallet import TARGET_ADDRESS, address_from_entropy
from octra_recon.workspace import init_workspace


class GitHubLexiconTests(unittest.TestCase):
    def test_extract_bip39_tokens_from_readme(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "The abandon ability about zoo words are BIP39 and challenge v2 bounty.\n"
                "Also hex deadbeefcafebabe0123456789abcdef\n",
                encoding="utf-8",
            )
            bip39 = _load_bip39_set()
            corpus = extract_corpus([root], bip39, max_files=10)
            self.assertGreaterEqual(corpus["bip39_unique"], 3)
            self.assertIn("abandon", corpus["bip39_token_counts"])
            self.assertTrue(any("challenge" in p.lower() or "bounty" in p.lower() for p in corpus["phrases"]))

    def test_brainwallet_hit_when_target_forced(self) -> None:
        """If we plant entropy that maps to a known address, hunter must find it."""
        # Use all-zero entropy address as synthetic target
        planted = address_from_entropy(bytes(16))
        synthetic_target = planted["address"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            init_workspace(ws)
            # empty repos → still has seed phrases + fixed patterns including all_zero
            # fixed all_zero is candidate #1 — only need a handful of derivations
            summary = run_github_lexicon(
                ws,
                target=synthetic_target,
                base=root,
                max_candidates=8,
                max_files=10,
                deep=False,
                roots=[],
                skip_tested=False,
            )
            self.assertGreaterEqual(summary["tested"], 1)
            self.assertGreaterEqual(summary["hits"], 1)
            self.assertTrue(any(h.get("match") for h in summary["hit_details"]))

    def test_generate_candidates_bounded(self) -> None:
        bip39 = _load_bip39_set()
        corpus = {
            "phrases": {"octra", "hfhe challenge"},
            "hex_blobs": {"aa" * 16},
            "b58_blobs": set(),
            "mnemonic_candidates": set(),
            "bip39_token_counts": __import__("collections").Counter(
                {"abandon": 5, "zoo": 3, "about": 2, "legal": 1}
            ),
        }
        cands = _generate_candidates(
            corpus, bip39, max_candidates=200, top_bip39=8, combo_pairs=True, deep=False
        )
        self.assertLessEqual(len(cands), 200)
        self.assertGreater(len(cands), 10)

    def test_real_target_no_hit_on_tiny_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            init_workspace(ws)
            (root / "note.md").write_text("octra hfhe pvac bounty seed\n", encoding="utf-8")
            summary = run_github_lexicon(
                ws,
                target=TARGET_ADDRESS,
                base=root,
                max_candidates=12,
                max_files=20,
                roots=[root],
                skip_tested=False,
            )
            self.assertEqual(summary["hits"], 0)
            self.assertGreater(summary["tested"], 0)


if __name__ == "__main__":
    unittest.main()
