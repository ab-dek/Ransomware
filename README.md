
This is a sample offline ransomware that encrypts users' files using AES-128 and RSA-2046 encryption algorithms. 
**NOTE! This project is intended for academic purposes only.**

---

### Features

- The project consists of two main components:
  - The ransomware executable with a built-in decryptor
  - `rsa_tool` — a CLI tool used for generating RSA key pairs and decrypting ciphertext using a private key
- Files are encrypted using AES in Galois/Counter Mode (GCM)
- The AES encryption key is itself encrypted using RSA-2046 (RSA-OAEP-2046 with SHA-256)
- A ransom note is displayed via a GUI using raygui
- Targets selected folders within the current user's home directory.
- works on both Windows and Linux.

---

### How It Works

To operate offline and avoid sending information to a decryption server, the attacker generates an RSA key pair first. the public key is hardcoded in the ransomware exe. During execution:

1.  The ransomware generates a random AES key to encrypt the victim's files.
2.  This AES key is encrypted with the harcoded RSA public key.
3.  The encrypted AES key is displayed in the ransom note GUI.
4.  The victim is instructed to pay a ransom and send their email, transaction ID, and the encrypted AES key to the attacker.
5.  Upon verifying the transaction, the attacker uses the private RSA key to decrypt the AES key and sends it back to the victim through a safe mailing service accessible via Tor.

---

### Usage

- Use `rsa_tool` to generate RSA key pairs for encryption and decryption.
- Run the ransomware executable on the target system to encrypt files.
- Use `rsa_tool` again to decrypt the encrypted aes key that will be used to recover the files.

---

### Screenshot

![Alt text](Screenshot.png?raw=true "Title")

---