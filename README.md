# SecureShare - Information Security Lab Mini Project

Encrypted (AES-256), integrity-checked (SHA-256) and signed (RSA-2048-PSS) file sharing for students.

## Run
    pip install flask cryptography requests
    python run_demo.py                      # automated demo: 12 attack/tamper tests + benchmarks -> RESULTS.md

    # manual use
    python server.py --port 5000            # dashboard at http://127.0.0.1:5000/dashboard
    python client.py -u alice register
    python client.py -u bob   register
    python client.py -u alice upload report.pdf bob --mode GCM     # or CBC
    python client.py -u bob   download 1
    python client.py -u bob   dashboard     # full decrypt + SHA-256 + signature check on every received file

## Pipeline
Upload (client): SHA-256(plaintext) -> RSA-PSS sign hash -> AES-256 encrypt with random key -> RSA-OAEP wrap key for recipient -> send ciphertext, wrapped key, IV, hash, signature.
Download (client): unwrap key -> decrypt -> recompute SHA-256 and compare with original -> verify sender signature. Mismatch = "File Tampered"; bad signature = "Signature Invalid". Unverified plaintext is never written to disk.
The server only stores ciphertext; private keys (password-encrypted PKCS#8) stay on the client.

## Files
crypto_utils.py | server.py (Flask + SQLite, scrypt-salted passwords, tokens, login lockout, dashboard) | client.py (CLI + library) | baseline_server.py (unprotected comparison) | run_demo.py (sniffer MITM standing in for Wireshark, tamper matrix, benchmarks)

## Real Wireshark
Capture on loopback with `tcp.port == 5000` (SecureShare) vs the baseline port, then Follow TCP Stream: baseline is readable text, SecureShare is base64 ciphertext.

## Viva notes
- GCM catches ciphertext tampering via its auth tag before the hash check; CBC has no integrity of its own, so there SHA-256 does the catching (run_demo shows both). Test T4 isolates the pure "Original SHA-256 != Received SHA-256" path.
- Public keys come from the server (trust-on-first-use); production would add key fingerprints or a CA.
- Use TLS when deploying (`server.py --cert cert.pem --key key.pem`). The demo uses plain HTTP so the sniffer can show the payload is already ciphertext; login credentials would be visible without TLS.
