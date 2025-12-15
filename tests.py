
import os
import asyncio
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import main as m


def _run(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=30)
    return asyncio.run(coro)


class TestCrypto(unittest.TestCase):
    def test_aesgcm_roundtrip(self):
        key = AESGCM.generate_key(bit_length=256)
        pt = os.urandom(1024 * 64)
        ct = m.aes_encrypt(pt, key)
        out = m.aes_decrypt(ct, key)
        self.assertEqual(pt, out)

    def test_file_roundtrip(self):
        key = AESGCM.generate_key(bit_length=256)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "a.bin"
            enc = td / "a.bin.aes"
            dec = td / "a.bin.dec"
            src.write_bytes(os.urandom(1024 * 1024 + 123))
            m.encrypt_file(src, enc, key)
            m.decrypt_file(enc, dec, key)
            self.assertEqual(src.read_bytes(), dec.read_bytes())


class TestDB(unittest.TestCase):
    def test_db_init_log_fetch(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)

            old_db = m.DB_PATH
            old_tmp = m.TMP_DIR

            try:
                m.DB_PATH = td / "chat_history.db.aes"
                m.TMP_DIR = td / "tmp"
                m.TMP_DIR.mkdir(parents=True, exist_ok=True)

                key = AESGCM.generate_key(bit_length=256)

                _run(m.init_db(key))
                _run(m.log_interaction("p1", "r1", key))
                rows = _run(m.fetch_history(key, limit=10))

                self.assertTrue(len(rows) >= 1)
                rid, ts, prompt, resp = rows[0]
                self.assertIn("p1", prompt)
                self.assertIn("r1", resp)
            finally:
                m.DB_PATH = old_db
                m.TMP_DIR = old_tmp


if __name__ == "__main__":
    unittest.main(verbosity=2)
