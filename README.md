## Overview

This project is a terminal-based chat application that implements secure message exchange using the RSA encryption algorithm and message integrity verification.
The system consists of a server and multiple clients communicating over sockets. Messages are encrypted before transmission and verified upon receipt to ensure both confidentiality and integrity.

## How to Run

### 1. Clone repository
- git clone <https://github.com/khrystynaa-sh/RSA.git>
- cd "folder_where_the_project_is"

### 2. Start the server
python server.py

You should see:

[server]: generating RSA keys...

[server]: ready, waiting for connections...

### 3. Start client(s)
Open a new terminal for each client:
python client.py

Then start chatting by typing messages.

## How should it look

<img width="785" height="208" alt="Знімок екрана 2026-04-16 230533" src="https://github.com/user-attachments/assets/1206816c-f4df-4ae5-a9a7-504897ce73e6" />
<img width="758" height="245" alt="Знімок екрана 2026-04-16 230543" src="https://github.com/user-attachments/assets/e5f04ac0-5217-4cc2-a10f-87af84c0a9dd" />
<img width="718" height="215" alt="Знімок екрана 2026-04-16 230552" src="https://github.com/user-attachments/assets/c3cd29a4-aece-4290-bfbb-8185a0bf738a" />

## How it works

### 1. Key Generation and Exchange
Each client and the server generate their own RSA key pair:
- Public key (e, n) is shared with others
- Private key (d, n) is kept secret

When a client connects:
- The server sends its public key
- The client sends its public key

### 2. Sending a Message
When a client sends a message:
- Compute SHA-256 hash of the message
- Encrypt the message using the receiver’s public key
- Send data in format: hash|encrypted_message

### 3. Receiving a Message
Upon receiving a message:
- Split received data into hash and encrypted message
- Decrypt message using private key
- Compute hash of decrypted message
- Compare hashes:
  
  If equal → message is valid

  If not → message was altered

## RSA Implementation Details
RSA is implemented manually without external cryptography libraries.
### Key steps:
Generates two large prime numbers p and q
Computes:
n = p * q
φ(n) = (p-1)(q-1)
Chooses public exponent e = 65537
Computes private exponent d such that:
d ≡ e⁻¹ mod φ(n)

Encryption:
c = m^e mod n

Decryption:
m = c^d mod n

Each character in the message is encrypted individually using its ASCII value.

## Message Integrity
Message integrity is ensured using SHA-256 from Python’s standard library:
- A hash is generated before encryption
- After decryption, the hash is recomputed
- If hashes do not match, the message is rejected

## Project Structure
.
├── client.py  # Client-side chat logic

├── server.py      # Server-side communication and broadcasting

├── rsa.py         # RSA implementation

└── README.md

## Conclusion
This project demonstrates how RSA encryption and hashing can be combined to build a simple secure communication system. It highlights key concepts of public-key cryptography and message integrity in a practical application.
