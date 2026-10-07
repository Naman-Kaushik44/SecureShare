"""One-command demo: starts SecureShare + plaintext baseline, sniffs the wire, runs the attack/tamper matrix and benchmarks.
Usage:  python run_demo.py        (writes RESULTS.md and results.json)"""
import os, sys, json, time, random, socket, sqlite3, shutil, tempfile, threading, statistics
import requests
from werkzeug.serving import make_server
import crypto_utils as cu
import logging; logging.getLogger("werkzeug").setLevel(logging.ERROR)
import server as ss, baseline_server as bs
from client import SecureShareClient

MARKER = b"CONFIDENTIAL: CS-LAB-7 answer key = 42; roll no 34 scored 98/100. "
PW = "correct-horse-battery"
TRIALS = 50


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def serve(app):
    p = free_port(); srv = make_server("127.0.0.1", p, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start(); return p


class Sniffer:
    """TCP man-in-the-middle that records every byte on the wire (stand-in for Wireshark)."""
    def __init__(self, target_port):
        self.target, self.captured, self.port = target_port, bytearray(), free_port()
        self.sock = socket.socket(); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port)); self.sock.listen(32)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            c, _ = self.sock.accept(); u = socket.create_connection(("127.0.0.1", self.target))
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, src, dst):
        try:
            while (d := src.recv(65536)):
                self.captured += d; dst.sendall(d)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try: s.shutdown(socket.SHUT_RDWR)
                except OSError: pass


def flip_bit(path, bitpos):
    b = bytearray(open(path, "rb").read()); b[bitpos // 8] ^= 1 << (bitpos % 8); open(path, "wb").write(b)


def sql(db, q, args=()):
    c = sqlite3.connect(db); c.execute(q, args); c.commit(); c.close()


def main():
    tmp = tempfile.mkdtemp(prefix="secureshare_demo_")
    data, keys = os.path.join(tmp, "data"), os.path.join(tmp, "keys")
    sp, bp = serve(ss.create_app(data)), serve(bs.create_app(os.path.join(tmp, "base")))
    S, B = f"http://127.0.0.1:{sp}", f"http://127.0.0.1:{bp}"
    dbp, store = os.path.join(data, "secureshare.db"), os.path.join(data, "storage")
    rows = []

    def rec(name, expected, observed, ok):
        rows.append(dict(test=name, expected=expected, observed=observed, passed=bool(ok)))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}\n        expected: {expected}\n        observed: {observed}")

    print(f"SecureShare demo  (server :{sp}, baseline :{bp})\n")
    doc = os.path.join(tmp, "lab_report.txt")
    open(doc, "wb").write(MARKER * 400 + os.urandom(2000))           # ~28 KB 'academic document'
    original = open(doc, "rb").read()

    users = {}
    for n in ("alice", "bob", "mallory", "dave"):
        users[n] = SecureShareClient(S, keys, n); assert users[n].register(PW).status_code == 201; users[n].login(PW)
    alice, bob, mallory, dave = (users[n] for n in ("alice", "bob", "mallory", "dave"))

    # ---- T1: baseline sniffing ------------------------------------------------------------
    sn_b = Sniffer(bp)
    requests.post(f"http://127.0.0.1:{sn_b.port}/upload", data=original)
    time.sleep(.2)
    rec("T1 Wireshark-style capture: plaintext baseline", "file contents readable on the wire",
        f"marker found in {len(sn_b.captured)} captured bytes: {MARKER[:30] in sn_b.captured}", MARKER[:30] in sn_b.captured)

    # ---- T2: SecureShare sniffing -----------------------------------------------------------
    sn_s = Sniffer(sp)
    a2, b2 = SecureShareClient(f"http://127.0.0.1:{sn_s.port}", keys, "alice"), SecureShareClient(f"http://127.0.0.1:{sn_s.port}", keys, "bob")
    a2.login(PW); b2.login(PW)
    fid = a2.upload(doc, "bob", "GCM").json()["id"]
    got = b2.download(fid, os.path.join(tmp, "out"))
    cap = bytes(sn_s.captured)
    leaked = MARKER[:30] in cap or b"CONFIDENTIAL" in cap
    rec("T2 capture of SecureShare traffic", "only ciphertext visible; no plaintext on the wire",
        f"plaintext found in {len(cap)} captured bytes: {leaked}; round-trip verdict: {got['verdict']}",
        not leaked and got["verdict"] == "Verified" and open(got["saved_to"], "rb").read() == original)
    with open(os.path.join(store, f"{fid}.bin"), "rb") as f:
        stored = f.read()
    rec("T2b server storage at rest", "stored blob is ciphertext", f"plaintext marker in stored file: {MARKER[:30] in stored}",
        MARKER[:30] not in stored)

    # ---- T3: ciphertext tamper, both AES modes, many random single-bit flips ------------------
    rng = random.Random(7)
    for mode in ("GCM", "CBC"):
        fid_m = alice.upload(doc, "bob", mode).json()["id"]
        path = os.path.join(store, f"{fid_m}.bin"); clean = open(path, "rb").read(); caught = 0; via_hash = 0
        for _ in range(TRIALS):
            flip_bit(path, rng.randrange(len(clean) * 8))
            v = bob.verify_record(bob.fetch(fid_m).json())
            caught += v["verdict"] == "File Tampered"; via_hash += "SHA-256" in v["reason"]
            open(path, "wb").write(clean)
        rec(f"T3 random 1-bit ciphertext flips (AES-{mode})", f"{TRIALS}/{TRIALS} flagged 'File Tampered'",
            f"{caught}/{TRIALS} flagged ({via_hash} by SHA-256 mismatch, {caught - via_hash} by cipher auth/padding failure)",
            caught == TRIALS)
        assert bob.verify_record(bob.fetch(fid_m).json())["verdict"] == "Verified"
    # baseline: same attack, no defence
    r = requests.post(f"{B}/upload", data=original).json()["id"]; bpath = os.path.join(tmp, "base", f"{r}.bin"); undetected = 0
    for _ in range(TRIALS):
        flip_bit(bpath, rng.randrange(len(original) * 8)); body = requests.get(f"{B}/download/{r}").content
        undetected += body != original; open(bpath, "wb").write(original)
    rec("T3b same bit flips against plaintext baseline", "tampering goes unnoticed (0% detection)",
        f"{undetected}/{TRIALS} downloads silently corrupted, 0 alerts raised", undetected == TRIALS)

    # ---- T4: tampered hash record -> pure SHA-256 mismatch path ------------------------------------
    fid_h = alice.upload(doc, "bob", "GCM").json()["id"]
    sql(dbp, "UPDATE files SET sha256=? WHERE id=?", (cu.sha256_hex(b"something else"), fid_h))
    v = bob.verify_record(bob.fetch(fid_h).json())
    rec("T4 modified hash record in database", "'File Tampered' (Original SHA-256 != Received SHA-256)",
        f"{v['verdict']} - {v['reason']}; signature_ok={v['sig_ok']}", v["verdict"] == "File Tampered" and not v["hash_ok"])

    # ---- T5: unauthorized access ----------------------------------------------------------------
    r1 = requests.get(f"{S}/api/files/{fid}"); r2 = requests.get(f"{S}/api/files/{fid}", headers={"Authorization": "Bearer forged"})
    r3 = mallory.fetch(fid); r4 = SecureShareClient(S, keys, "alice").login("wrong-password")
    rec("T5 unauthorized access", "no token -> 401; forged token -> 401; other user -> 403; bad password -> 401",
        f"{r1.status_code}; {r2.status_code}; {r3.status_code}; {r4.status_code}",
        (r1.status_code, r2.status_code, r3.status_code, r4.status_code) == (401, 401, 403, 401))
    codes = [SecureShareClient(S, keys, "dave").login("bad-pass-x").status_code for _ in range(6)]
    rec("T5b brute-force lockout", "6th attempt throttled (429)", f"status codes {codes}", codes[-1] == 429)

    # ---- T6: forged signatures ----------------------------------------------------------------------
    mallory.sig_priv = cu.gen_rsa()                                  # key the server has never seen
    r = mallory.upload(doc, "bob")
    rec("T6a upload signed with unregistered key", "server rejects (400 invalid digital signature)",
        f"{r.status_code} {r.json()}", r.status_code == 400)
    fid_s = alice.upload(doc, "bob").json()["id"]; h = sqlite3.connect(dbp).execute("SELECT sha256 FROM files WHERE id=?", (fid_s,)).fetchone()[0]
    sql(dbp, "UPDATE files SET signature=? WHERE id=?", (cu.sign(mallory.sig_priv, h.encode()), fid_s))
    v = bob.verify_record(bob.fetch(fid_s).json())
    rec("T6b signature swapped for attacker's at rest", "recipient rejects: sender authenticity fails",
        f"{v['verdict']} (hash_ok={v['hash_ok']}, sig_ok={v['sig_ok']})", v["verdict"] == "Signature Invalid")
    out = bob.download(fid_s, os.path.join(tmp, "out2"))
    rec("T6c unverified file is never written to disk", "no output file for forged file", f"saved_to present: {'saved_to' in out}", "saved_to" not in out)

    # ---- Benchmarks -----------------------------------------------------------------------------------
    print("\nBenchmarking ...")
    kp_enc, kp_sig = cu.gen_rsa(), cu.gen_rsa(); bench = []
    t = lambda f, n: statistics.mean([(lambda s: (f(), time.perf_counter() - s)[1])(time.perf_counter()) for _ in range(n)]) * 1000
    for kb in (10, 100, 1024, 5120):
        pt = os.urandom(kb * 1024); n = 5 if kb <= 1024 else 3; row = dict(size_kb=kb, sha256_ms=t(lambda: cu.sha256_hex(pt), n))
        for m in ("GCM", "CBC"):
            k, iv, ct = cu.aes_encrypt(pt, m)
            row[f"enc_{m}_ms"] = t(lambda: cu.aes_encrypt(pt, m), n); row[f"dec_{m}_ms"] = t(lambda: cu.aes_decrypt(k, iv, ct, m), n)
        bench.append(row)
    d = cu.sha256_hex(b"x").encode(); sg = cu.sign(kp_sig, d); wk = cu.wrap_key(kp_enc.public_key(), os.urandom(32))
    asym = dict(rsa_sign_ms=t(lambda: cu.sign(kp_sig, d), 10), rsa_verify_ms=t(lambda: cu.verify(kp_sig.public_key(), sg, d), 10),
                key_wrap_ms=t(lambda: cu.wrap_key(kp_enc.public_key(), os.urandom(32)), 10), key_unwrap_ms=t(lambda: cu.unwrap_key(kp_enc, wk), 10))
    e2e = []
    for kb in (100, 1024):
        f = os.path.join(tmp, f"b{kb}.bin"); open(f, "wb").write(os.urandom(kb * 1024)); data_b = open(f, "rb").read()
        def sec():
            i = alice.upload(f, "bob").json()["id"]; assert bob.download(i, os.path.join(tmp, "o"))["verdict"] == "Verified"
        def base():
            i = requests.post(f"{B}/upload", data=data_b).json()["id"]; requests.get(f"{B}/download/{i}").content
        e2e.append(dict(size_kb=kb, baseline_ms=t(base, 3), secureshare_ms=t(sec, 3)))

    # ---- Report ------------------------------------------------------------------------------------------
    passed = sum(r["passed"] for r in rows)
    md = ["# SecureShare - Test & Benchmark Results\n", f"**{passed}/{len(rows)} security tests passed.**\n",
          "## Attack / tamper matrix\n", "| Test | Expected | Observed | Result |", "|---|---|---|---|"]
    md += [f"| {r['test']} | {r['expected']} | {r['observed']} | {'PASS' if r['passed'] else 'FAIL'} |" for r in rows]
    md += ["\n## Symmetric / hash cost (ms, mean)\n", "| Size | SHA-256 | GCM enc | GCM dec | CBC enc | CBC dec |", "|---|---|---|---|---|---|"]
    md += [f"| {b['size_kb']} KB | {b['sha256_ms']:.2f} | {b['enc_GCM_ms']:.2f} | {b['dec_GCM_ms']:.2f} | {b['enc_CBC_ms']:.2f} | {b['dec_CBC_ms']:.2f} |" for b in bench]
    md += ["\n## Asymmetric operations, size-independent (ms, mean)\n", "| RSA-2048 sign | verify | key wrap | key unwrap |", "|---|---|---|---|",
           f"| {asym['rsa_sign_ms']:.2f} | {asym['rsa_verify_ms']:.2f} | {asym['key_wrap_ms']:.2f} | {asym['key_unwrap_ms']:.2f} |",
           "\n## End-to-end upload + verified download vs plaintext baseline (loopback, ms)\n", "| Size | Baseline | SecureShare | Overhead |", "|---|---|---|---|"]
    md += [f"| {e['size_kb']} KB | {e['baseline_ms']:.1f} | {e['secureshare_ms']:.1f} | {e['secureshare_ms'] - e['baseline_ms']:+.1f} |" for e in e2e]
    open("RESULTS.md", "w").write("\n".join(md) + "\n"); json.dump(dict(tests=rows, bench=bench, asym=asym, e2e=e2e), open("results.json", "w"), indent=2)
    print("\n" + "\n".join(md[-12:]) + f"\n\nSUMMARY: {passed}/{len(rows)} tests passed. Full report: RESULTS.md")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(0 if passed == len(rows) else 1)


if __name__ == "__main__":
    main()
