/* SecureShare browser crypto (WebCrypto). Wire-compatible with the Python client:
   SHA-256 -> RSA-2048-PSS(salt 32) sign -> AES-256-GCM/CBC -> RSA-OAEP(SHA-256) key wrap. */
(function (root) {
  'use strict';
  const C = root.crypto, S = C.subtle, TE = new TextEncoder();
  const b64e = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const hex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  const toPem = buf => '-----BEGIN PUBLIC KEY-----\n' + b64e(new Uint8Array(buf)).match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----\n';
  const fromPem = pem => b64d(pem.replace(/-----[^-]+-----|\s/g, ''));
  const RSA = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };

  async function api(base, token, method, path, body) {
    const r = await fetch(base + path, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}), body: body ? JSON.stringify(body) : undefined });
    let json = {}; try { json = await r.json(); } catch (e) {}
    return { ok: r.ok, status: r.status, json };
  }

  // ---- password-protected key vault (PBKDF2 -> AES-GCM); private keys never leave the browser ----
  async function pwKey(pw, salt) {
    const m = await S.importKey('raw', TE.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return S.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, m, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function seal(obj, pw) {
    const salt = C.getRandomValues(new Uint8Array(16)), iv = C.getRandomValues(new Uint8Array(12));
    const ct = await S.encrypt({ name: 'AES-GCM', iv }, await pwKey(pw, salt), TE.encode(JSON.stringify(obj)));
    return { salt: b64e(salt), iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
  }
  async function unseal(v, pw) {
    const pt = await S.decrypt({ name: 'AES-GCM', iv: b64d(v.iv) }, await pwKey(pw, b64d(v.salt)), b64d(v.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  async function register(base, user, pw, store) {
    const enc = await S.generateKey(Object.assign({ name: 'RSA-OAEP' }, RSA), true, ['encrypt', 'decrypt']);
    const sig = await S.generateKey(Object.assign({ name: 'RSA-PSS' }, RSA), true, ['sign', 'verify']);
    const vault = await seal({ enc: b64e(new Uint8Array(await S.exportKey('pkcs8', enc.privateKey))), sig: b64e(new Uint8Array(await S.exportKey('pkcs8', sig.privateKey))) }, pw);
    const r = await api(base, null, 'POST', '/api/register', { username: user, password: pw, enc_pub: toPem(await S.exportKey('spki', enc.publicKey)), sig_pub: toPem(await S.exportKey('spki', sig.publicKey)) });
    if (r.ok) store.setItem('ss_vault_' + user, JSON.stringify(vault));
    return r;
  }

  async function login(base, user, pw, store) {
    const r = await api(base, null, 'POST', '/api/login', { username: user, password: pw });
    if (!r.ok) return { error: r.json.error || 'login failed', status: r.status };
    const raw = store.getItem('ss_vault_' + user);
    if (!raw) return { error: 'no local keys for this user on this device (register here first)' };
    let v; try { v = await unseal(JSON.parse(raw), pw); } catch (e) { return { error: 'could not unlock local key vault' }; }
    return { base, user, token: r.json.token, cache: {},
      encPriv: await S.importKey('pkcs8', b64d(v.enc), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']),
      sigPriv: await S.importKey('pkcs8', b64d(v.sig), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']) };
  }

  async function userKeys(s, name) {
    if (!s.cache[name]) { const r = await api(s.base, s.token, 'GET', '/api/users/' + encodeURIComponent(name) + '/keys'); if (!r.ok) throw new Error(r.json.error || 'unknown user'); s.cache[name] = r.json; }
    return s.cache[name];
  }

  async function upload(s, recipient, filename, bytes, mode) {
    mode = mode || 'GCM';
    const digest = hex(await S.digest('SHA-256', bytes));                                     // 1. fingerprint
    const sig = new Uint8Array(await S.sign({ name: 'RSA-PSS', saltLength: 32 }, s.sigPriv, TE.encode(digest))); // 2. sign
    const alg = mode === 'GCM' ? 'AES-GCM' : 'AES-CBC';
    const key = await S.generateKey({ name: alg, length: 256 }, true, ['encrypt', 'decrypt']); // 3. AES-256
    const iv = C.getRandomValues(new Uint8Array(mode === 'GCM' ? 12 : 16));
    const ct = new Uint8Array(await S.encrypt({ name: alg, iv }, key, bytes));
    const rk = await S.importKey('spki', fromPem((await userKeys(s, recipient)).enc_pub), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const wrapped = new Uint8Array(await S.encrypt({ name: 'RSA-OAEP' }, rk, await S.exportKey('raw', key))); // 4. wrap key
    const r = await api(s.base, s.token, 'POST', '/api/files', { recipient, filename, mode, iv: b64e(iv), wrapped_key: b64e(wrapped), sha256: digest, signature: b64e(sig), ciphertext: b64e(ct) });
    return { ok: r.ok, status: r.status, id: r.json.id, error: r.json.error, sha256: digest, ctBytes: ct.length, ctPreview: hex(ct.subarray(0, 24)) };
  }

  async function verifyRecord(s, rec) {
    const out = { filename: rec.filename, sender: rec.sender, hashOk: false, sigOk: false, verdict: null, reason: '', plaintext: null };
    const pub = await S.importKey('spki', fromPem((await userKeys(s, rec.sender)).sig_pub), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
    try { out.sigOk = await S.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, b64d(rec.signature), TE.encode(rec.sha256)); } catch (e) {}
    let pt;
    try {
      const alg = rec.mode === 'GCM' ? 'AES-GCM' : 'AES-CBC';
      const raw = await S.decrypt({ name: 'RSA-OAEP' }, s.encPriv, b64d(rec.wrapped_key));
      const key = await S.importKey('raw', raw, { name: alg }, false, ['decrypt']);
      pt = new Uint8Array(await S.decrypt({ name: alg, iv: b64d(rec.iv) }, key, b64d(rec.ciphertext)));
    } catch (e) { out.verdict = 'File Tampered'; out.reason = 'decryption failed (' + (e.name || 'error') + ')'; return out; }
    out.hashOk = hex(await S.digest('SHA-256', pt)) === rec.sha256;
    if (!out.hashOk) { out.verdict = 'File Tampered'; out.reason = 'Original SHA-256 != Received SHA-256'; }
    else if (!out.sigOk) { out.verdict = 'Signature Invalid'; out.reason = 'sender signature did not verify'; }
    else { out.verdict = 'Verified'; out.reason = 'hash matches and signature valid'; out.plaintext = pt; }
    return out;
  }

  const list = async s => (await api(s.base, s.token, 'GET', '/api/files')).json.files || [];
  const fetchRecord = async (s, id) => { const r = await api(s.base, s.token, 'GET', '/api/files/' + id); return r.ok ? r.json : null; };
  const SC = { register, login, upload, verifyRecord, list, fetchRecord, b64e, b64d };
  root.SC = SC; if (typeof module !== 'undefined') module.exports = SC;
})(globalThis);
