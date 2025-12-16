#!/usr/bin/env python3
import os, sys, hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK = 1024 * 1024

def sha256_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def hkdf32(secret: bytes, info: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)

def encrypt_file_gcm(src: Path, dst: Path, key32: bytes):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key32), modes.GCM(nonce)).encryptor()
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    with src.open("rb") as fin, tmp.open("wb") as fout:
        fout.write(nonce)
        while True:
            buf = fin.read(CHUNK)
            if not buf:
                break
            fout.write(enc.update(buf))
        enc.finalize()
        fout.write(enc.tag)
    tmp.replace(dst)

def decrypt_bytes_gcm(blob: bytes, key32: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("bad blob")
    nonce = blob[:12]
    tag = blob[-16:]
    ct = blob[12:-16]
    dec = Cipher(algorithms.AES(key32), modes.GCM(nonce, tag)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt

def encrypt_bytes_gcm(pt: bytes, key32: bytes) -> bytes:
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key32), modes.GCM(nonce)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    return nonce + ct + enc.tag

def main():
    # Usage:
    #   BOOTSTRAP_SECRET=... python tools/prepare_model.py path/to/model.gguf models/
    secret = os.environ.get("BOOTSTRAP_SECRET", "").encode("utf-8")
    if not secret:
        print("Missing BOOTSTRAP_SECRET env var", file=sys.stderr)
        sys.exit(2)

    if len(sys.argv) != 3:
        print("Usage: prepare_model.py <model.gguf> <out_models_dir>", file=sys.stderr)
        sys.exit(2)

    src = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    model_name = src.name
    out_enc = out_dir / (model_name + ".aes")
    out_wrap = out_dir / (model_name + ".mdk.wrap")
    out_sha  = out_dir / (model_name + ".sha256")

    # Model Data Key (MDK) encrypts the GGUF.
    mdk = os.urandom(32)

    # Bootstrap key wraps the MDK (small file).
    bootstrap_key = hkdf32(secret, b"qroadscan/bootstrap/v1")

    # Encrypt model
    encrypt_file_gcm(src, out_enc, mdk)

    # Wrap MDK
    wrapped = encrypt_bytes_gcm(mdk, bootstrap_key)
    out_wrap.write_bytes(wrapped)

    # Integrity (optional): store sha256 of plaintext model
    out_sha.write_text(sha256_file(src), encoding="utf-8")

    print("Wrote:", out_enc)
    print("Wrote:", out_wrap)
    print("Wrote:", out_sha)

if __name__ == "__main__":
    main()
