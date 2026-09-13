from pathlib import Path
from encryption_toolkit import caesar_transform, decrypt_aes, encrypt_aes

message = b"Authorized InfozaTech encryption demo."
password = "Training-Only-Password-2026!"

ciphertext = encrypt_aes(message, password)
recovered = decrypt_aes(ciphertext, password)
assert recovered == message
assert caesar_transform("Hello InfozaTech", 3) == "Khoor LqircdWhfk"
assert caesar_transform("Khoor LqircdWhfk", -3) == "Hello InfozaTech"
print("AES-GCM round-trip: PASS")
print("Caesar encrypt/decrypt: PASS")
print("Passwords and plaintext were used only in memory for this test.")
