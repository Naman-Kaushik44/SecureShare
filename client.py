"""SecureShare client. All cryptography happens HERE, before upload / after download."""
import os, sys, json, base64, argparse, getpass
import requests
import crypto_utils as cu

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)


class SecureShareClient:
    def __init__(self, server, home, user):
        self.server, self.user = server.rstrip("/"), user
        self.home = os.path.join(home, user)
        self.http, self.token = requests.Session(), None

    def _h(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def register(self, password):
        """Generate two RSA-2048 key pairs locally (encryption + signing); private keys never leave the machine."""
        os.makedirs(self.home, exist_ok=True)
        enc, sig = cu.gen_rsa(), cu.gen_rsa()
        for name, k in (("enc", enc), ("sig", sig)):
            with open(os.path.join(self.home, f"{name}.pem"), "wb") as f:
                f.write(cu.priv_to_pem(k, password))
        return self.http.post(f"{self.server}/api/register", json=dict(
            username=self.user, password=password,
            enc_pub=cu.pub_to_pem(enc).decode(), sig_pub=cu.pub_to_pem(sig).decode()))

    def login(self, password):
        r = self.http.post(f"{self.server}/api/login", json=dict(username=self.user, password=password))
        if r.ok:
            self.token = r.json()["token"]
            load = lambda n: cu.load_priv(open(os.path.join(self.home, f"{n}.pem"), "rb").read(), password)
            self.enc_priv, self.sig_priv = load("enc"), load("sig")
        return r

    def _keys(self, name):
        r = self.http.get(f"{self.server}/api/users/{name}/keys", headers=self._h())
        r.raise_for_status()
        return r.json()

    def upload(self, path, recipient, mode="GCM"):
        data = open(path, "rb").read()
        digest = cu.sha256_hex(data)                                  # 1. fingerprint plaintext
        signature = cu.sign(self.sig_priv, digest.encode())           # 2. sign the hash
        key, iv, ct = cu.aes_encrypt(data, mode)                      # 3. AES-256 encrypt
        wrapped = cu.wrap_key(cu.load_pub(self._keys(recipient)["enc_pub"].encode()), key)  # 4. RSA-wrap key
        return self.http.post(f"{self.server}/api/files", headers=self._h(), json=dict(
            recipient=recipient, filename=os.path.basename(path), mode=mode, iv=b64e(iv), wrapped_key=b64e(wrapped),
            sha256=digest, signature=b64e(signature), ciphertext=b64e(ct)))

    def fetch(self, fid):
        return self.http.get(f"{self.server}/api/files/{fid}", headers=self._h())

    def verify_record(self, rec):
        """Decrypt, recompute SHA-256, compare with the original, verify sender's signature."""
        out = dict(filename=rec["filename"], sender=rec["sender"], hash_ok=False, sig_ok=False,
                   verdict=None, reason="", plaintext=None)
        pub = cu.load_pub(self._keys(rec["sender"])["sig_pub"].encode())
        out["sig_ok"] = cu.verify(pub, b64d(rec["signature"]), rec["sha256"].encode())
        try:
            key = cu.unwrap_key(self.enc_priv, b64d(rec["wrapped_key"]))
            pt = cu.aes_decrypt(key, b64d(rec["iv"]), b64d(rec["ciphertext"]), rec["mode"])
        except Exception as e:
            out.update(verdict="File Tampered", reason=f"decryption failed ({e})")
            return out
        out["hash_ok"] = cu.sha256_hex(pt) == rec["sha256"]
        if not out["hash_ok"]:
            out.update(verdict="File Tampered", reason="Original SHA-256 != Received SHA-256")
        elif not out["sig_ok"]:
            out.update(verdict="Signature Invalid", reason="sender signature did not verify")
        else:
            out.update(verdict="Verified", reason="hash matches and signature valid", plaintext=pt)
        return out

    def download(self, fid, outdir="."):
        r = self.fetch(fid)
        if not r.ok:
            return dict(verdict="Denied", reason=f"HTTP {r.status_code}: {r.json().get('error')}")
        res = self.verify_record(r.json())
        if res["plaintext"] is not None:                              # only write verified files to disk
            os.makedirs(outdir, exist_ok=True)
            res["saved_to"] = os.path.join(outdir, res["filename"])
            open(res["saved_to"], "wb").write(res["plaintext"])
        return res

    def dashboard(self):
        rows = self.http.get(f"{self.server}/api/files", headers=self._h()).json()["files"]
        for f in rows:
            if f["recipient"] == self.user:
                v = self.verify_record(self.fetch(f["id"]).json())
                status = f"{v['verdict']} ({v['reason']})"
            else:
                status = "sent"
            print(f"#{f['id']:<3} {f['filename']:<24} {f['sender']} -> {f['recipient']:<8} "
                  f"AES-256-{f['mode']}  storage={f['storage']:<8} sig={f['signature']:<7} {status}")


def main():
    ap = argparse.ArgumentParser(description="SecureShare CLI")
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    ap.add_argument("--home", default="./keys")
    ap.add_argument("-u", "--user", required=True)
    ap.add_argument("-p", "--password")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("register")
    up = sub.add_parser("upload"); up.add_argument("file"); up.add_argument("to"); up.add_argument("--mode", default="GCM", choices=["GCM", "CBC"])
    dl = sub.add_parser("download"); dl.add_argument("id", type=int); dl.add_argument("--out", default="downloads")
    sub.add_parser("dashboard")
    a = ap.parse_args()
    pw = a.password or getpass.getpass("password: ")
    c = SecureShareClient(a.server, a.home, a.user)
    if a.cmd == "register":
        r = c.register(pw); print(r.status_code, r.json()); return
    r = c.login(pw)
    if not r.ok:
        sys.exit(f"login failed: {r.json()}")
    if a.cmd == "upload":
        r = c.upload(a.file, a.to, a.mode); print(r.status_code, r.json())
    elif a.cmd == "download":
        res = c.download(a.id, a.out); res.pop("plaintext", None)
        print(json.dumps(res, indent=2)); sys.exit(0 if res["verdict"] == "Verified" else 2)
    else:
        c.dashboard()


if __name__ == "__main__":
    main()
