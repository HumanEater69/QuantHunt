import unittest
import json
from pathlib import Path
from backend.main import _offline_chain_reply

class OfflineKBExpansionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):

        kb_gen_path = Path("backend/kb_generator.py")
        if kb_gen_path.exists():
            import subprocess
            subprocess.run(["python", str(kb_gen_path)], check=True)

    def test_who_am_i_fused(self):
        reply, intent = _offline_chain_reply("who am i")
        self.assertEqual(intent, "kb_who_am_i")
        self.assertIn("Quanthunt", reply)

    def test_meaning_of_life_fused(self):
        reply, intent = _offline_chain_reply("what is the meaning of life")
        self.assertEqual(intent, "kb_what_is_the_meaning_of_life")
        self.assertIn("42", reply)

    def test_quantum_break_blockchain_fused(self):
        reply, intent = _offline_chain_reply("can quantum computers break block chain")
        self.assertEqual(intent, "kb_can_quantum_computers_break_block_chain")
        self.assertIn("ECC and RSA signatures", reply)

    def test_joke_fused(self):
        reply, intent = _offline_chain_reply("tell me a joke")
        self.assertEqual(intent, "kb_tell_me_a_joke")
        self.assertIn("RSA key", reply)

if __name__ == "__main__":
    unittest.main()
