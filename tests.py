import os, asyncio, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import app as m

class TestCrypto(unittest.TestCase):
    def test_aesgcm_roundtrip(self):
        key = AESGCM.generate_key(256)
        pt = os.urandom(1024 * 64)
        ct = m.aes_encrypt(pt, key)
        out = m.aes_decrypt(ct, key)
        self.assertEqual(pt, out)

    def test_stream_file_roundtrip(self):
        key = AESGCM.generate_key(256)
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
                key = AESGCM.generate_key(256)
                asyncio.run(m.init_db(key))
                asyncio.run(m.log_interaction("p1", "r1", key))
                rows = asyncio.run(m.fetch_history(key, limit=10))
                self.assertTrue(len(rows) >= 1)
                rid, ts, prompt, resp = rows[0]
                self.assertIn("p1", prompt)
                self.assertIn("r1", resp)
            finally:
                m.DB_PATH = old_db
                m.TMP_DIR = old_tmp

if __name__ == "__main__":
    unittest.main()
