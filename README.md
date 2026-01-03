# Pure Python TLS 1.2 Implementation

A custom, low-level implementation of a **TLS 1.2 Server** written in Python.
Unlike standard servers that rely on the `ssl` module for the handshake, this project manually implements the TLS protocol flow, packet parsing, and cryptographic operations over raw TCP sockets.

## 🚀 Features

- Raw TCP socket handling with manual parsing of TLS record layers
- Full TLS 1.2 handshake implementation
- ECDHE key exchange using SECP256R1
- RSA signatures for Server Key Exchange verification
- AES-128-GCM encryption for secure data transfer
- TCP packet buffering and state management
- Handshake transcript hashing and Finished message verification (SHA256)
- Ability to serve a basic HTTPS response (HTTP/1.1 200 OK)

## 🛠️ Tech Stack

- Language: Python 3.x
- Cryptography Library: cryptography (used only for primitives such as AES, RSA, and elliptic curves; all protocol logic is custom)
- Tools: OpenSSL, curl, Wireshark

## 📦 Installation

Clone the repository and install dependencies:

git clone https://github.com/tomerpaik/TLS_connection.git
cd TLS_connection
pip install cryptography

## 🔑 Certificate and Key Generation

This project requires a locally generated RSA private key and a self-signed certificate.
Private keys and certificates are NOT stored in the repository.

Generate the required files using OpenSSL:

1. Generate a 2048-bit RSA private key:
openssl genrsa -out server.key 2048

2. Generate a self-signed certificate:
openssl req -new -x509 -key server.key -out server.crt -days 365

3. Convert the certificate to DER format (required by the server):
openssl x509 -in server.crt -outform DER -out server.der

The following files will be created locally:
- server.key (private key)
- server.crt (PEM certificate)
- server.der (DER-encoded certificate)


## ▶️ Usage

Start the TLS server:

python server.py

In a separate terminal, connect using curl:

curl -v --insecure https://localhost:4433

You should see a successful TLS handshake and receive a response such as:

Hello from Python TLS!

## 📚 What I Learned

Through building this project, I gained a deep understanding of:

- The structure of TLS records (Content Type, Version, Length)
- How ClientHello and ServerHello negotiate cipher suites
- The mathematics and flow of ECDHE shared secret derivation
- How AES-GCM uses nonces and Additional Authenticated Data (AAD) to prevent tampering
- How TLS handshake transcripts are hashed and verified
- Debugging binary network protocols using Wireshark and OpenSSL tools

## ⚠️ Disclaimer

This project is for educational purposes only.
It demonstrates how TLS works internally and omits many security checks, extensions, and hardening steps required for production-grade systems.
It should NOT be used in real-world or commercial environments.
