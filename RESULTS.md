# SecureShare - Test & Benchmark Results

**12/12 security tests passed.**

## Attack / tamper matrix

| Test | Expected | Observed | Result |
|---|---|---|---|
| T1 Wireshark-style capture: plaintext baseline | file contents readable on the wire | marker found in 28755 captured bytes: True | PASS |
| T2 capture of SecureShare traffic | only ciphertext visible; no plaintext on the wire | plaintext found in 82156 captured bytes: False; round-trip verdict: Verified | PASS |
| T2b server storage at rest | stored blob is ciphertext | plaintext marker in stored file: False | PASS |
| T3 random 1-bit ciphertext flips (AES-GCM) | 50/50 flagged 'File Tampered' | 50/50 flagged (0 by SHA-256 mismatch, 50 by cipher auth/padding failure) | PASS |
| T3 random 1-bit ciphertext flips (AES-CBC) | 50/50 flagged 'File Tampered' | 50/50 flagged (50 by SHA-256 mismatch, 0 by cipher auth/padding failure) | PASS |
| T3b same bit flips against plaintext baseline | tampering goes unnoticed (0% detection) | 50/50 downloads silently corrupted, 0 alerts raised | PASS |
| T4 modified hash record in database | 'File Tampered' (Original SHA-256 != Received SHA-256) | File Tampered - Original SHA-256 != Received SHA-256; signature_ok=False | PASS |
| T5 unauthorized access | no token -> 401; forged token -> 401; other user -> 403; bad password -> 401 | 401; 401; 403; 401 | PASS |
| T5b brute-force lockout | 6th attempt throttled (429) | status codes [401, 401, 401, 401, 401, 429] | PASS |
| T6a upload signed with unregistered key | server rejects (400 invalid digital signature) | 400 {'error': 'invalid digital signature'} | PASS |
| T6b signature swapped for attacker's at rest | recipient rejects: sender authenticity fails | Signature Invalid (hash_ok=True, sig_ok=False) | PASS |
| T6c unverified file is never written to disk | no output file for forged file | saved_to present: False | PASS |

## Symmetric / hash cost (ms, mean)

| Size | SHA-256 | GCM enc | GCM dec | CBC enc | CBC dec |
|---|---|---|---|---|---|
| 10 KB | 0.01 | 0.01 | 0.01 | 0.03 | 0.01 |
| 100 KB | 0.09 | 0.02 | 0.02 | 0.17 | 0.04 |
| 1024 KB | 0.86 | 0.58 | 0.62 | 2.71 | 1.55 |
| 5120 KB | 4.41 | 2.38 | 2.34 | 13.25 | 7.52 |

## Asymmetric operations, size-independent (ms, mean)

| RSA-2048 sign | verify | key wrap | key unwrap |
|---|---|---|---|
| 0.38 | 0.05 | 0.05 | 0.41 |

## End-to-end upload + verified download vs plaintext baseline (loopback, ms)

| Size | Baseline | SecureShare | Overhead |
|---|---|---|---|
| 100 KB | 17.6 | 42.2 | +24.6 |
| 1024 KB | 31.3 | 90.2 | +58.9 |
