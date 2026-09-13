# Encryption & Decryption Toolkit

An educational Python toolkit that demonstrates a classical Caesar cipher and a modern authenticated symmetric cipher, AES-256-GCM.

## Safety Notes

Use only test data that you own. The toolkit does not store passwords. Never commit real passwords, secret keys, private documents, or production encrypted data to GitHub.

## Requirements

- Python 3.8 or later
- `cryptography` package

Install the dependency:

```bash
python3 -m pip install cryptography
```

## 1. Caesar Cipher

The Caesar cipher is included for learning only and is not secure for real data:

```bash
python3 encryption_toolkit.py caesar encrypt "Hello InfozaTech" --shift 3
python3 encryption_toolkit.py caesar decrypt "Khoor Lqircdwhfk" --shift 3
```

## 2. AES-256-GCM

AES-GCM provides modern symmetric encryption with authentication. The tool derives a key from an interactively entered passphrase using PBKDF2-HMAC-SHA256, a random salt, and a random nonce.

Encrypt a small test file:

```bash
python3 encryption_toolkit.py aes encrypt sample_message.txt encrypted.json
```

Decrypt it:

```bash
python3 encryption_toolkit.py aes decrypt encrypted.json recovered_message.txt
```

The password is entered interactively and is not included in the command line.

## Classical vs Modern Encryption

| Method | Strength | Limitation |
|---|---|---|
| Caesar | Easy to understand and useful for teaching substitution concepts | Easily broken and unsuitable for protecting real information |
| AES-256-GCM | Modern authenticated encryption when used with secure key management | Requires secure password/key handling and correct nonce usage |

## Limitations

This is an educational toolkit for small local files. It is not a replacement for a reviewed production encryption system or a full key-management service. AES-GCM does not protect a weak password, and losing the password means the encrypted content cannot be recovered.
