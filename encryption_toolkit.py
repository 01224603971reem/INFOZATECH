#!/usr/bin/env python3
"""Educational encryption toolkit.

Includes a Caesar cipher for learning and AES-256-GCM for modern authenticated
symmetric encryption. Passwords are entered interactively and are never saved.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = "INFOZATECH-AES-GCM-v1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000


def caesar_transform(text: str, shift: int) -> str:
    result = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(char)
    return "".join(result)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_aes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC.encode("utf-8"))
    envelope = {
        "format": MAGIC,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


def decrypt_aes(envelope_bytes: bytes, password: str) -> bytes:
    envelope = json.loads(envelope_bytes.decode("utf-8"))
    if envelope.get("format") != MAGIC:
        raise ValueError("Unsupported encrypted file format")
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, MAGIC.encode("utf-8"))


def password_for(action: str) -> str:
    first = getpass.getpass(f"Enter password to {action}: ")
    if not first:
        raise ValueError("Password cannot be empty")
    return first


def main() -> int:
    parser = argparse.ArgumentParser(description="Educational Caesar and AES-GCM toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    caesar = sub.add_parser("caesar", help="Demonstrate a classical Caesar cipher")
    caesar.add_argument("action", choices=("encrypt", "decrypt"))
    caesar.add_argument("text")
    caesar.add_argument("--shift", type=int, default=3)

    aes = sub.add_parser("aes", help="Encrypt or decrypt a small file with AES-256-GCM")
    aes.add_argument("action", choices=("encrypt", "decrypt"))
    aes.add_argument("input", type=Path)
    aes.add_argument("output", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "caesar":
            shift = args.shift if args.action == "encrypt" else -args.shift
            print(caesar_transform(args.text, shift))
            return 0

        password = password_for(args.action)
        if args.action == "encrypt":
            args.output.write_bytes(encrypt_aes(args.input.read_bytes(), password))
            print(f"Encrypted file written to: {args.output}")
        else:
            args.output.write_bytes(decrypt_aes(args.input.read_bytes(), password))
            print(f"Decrypted file written to: {args.output}")
        return 0
    except FileNotFoundError as error:
        print(f"ERROR: File not found: {error.filename}", file=sys.stderr)
        return 1
    except (ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("ERROR: Decryption failed or the encrypted data is invalid.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
