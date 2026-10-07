(() => {
  const $ = id => document.getElementById(id), base = location.origin;
  let S = null;
  const say = (el, t, bad) => { el.textContent = t; el.className = bad ? 'msg bad' : 'msg'; };
  const chip = (text, good) => { const s = document.createElement('span'); s.className = 's ' + (good ? 'ok' : 'bad'); s.textContent = text; return s; };
  const creds = () => [$('user').value.trim(), $('pw').value];

  $('register').onclick = async () => {
    const [u, p] = creds(); say($('authmsg'), 'Generating RSA-2048 keys...');
    const r = await SC.register(base, u, p, localStorage);
    say($('authmsg'), r.ok ? 'Registered. You can log in now.' : (r.json.error || 'registration failed'), !r.ok);
  };
  $('login').onclick = async () => {
    const [u, p] = creds(); const s = await SC.login(base, u, p, localStorage);
    if (s.error) return say($('authmsg'), s.error, true);
    S = s; $('auth').hidden = true; $('app').hidden = false; $('who').textContent = 'SIGNED IN AS ' + u.toUpperCase(); refresh();
  };
  $('logout').onclick = () => { S = null; $('app').hidden = true; $('auth').hidden = false; $('pw').value = ''; };

  $('send').onclick = async () => {
    const f = $('file').files[0], to = $('to').value.trim(); if (!f || !to) return say($('sendmsg'), 'Choose a recipient and a file.', true);
    say($('sendmsg'), 'Encrypting...');
    try {
      const r = await SC.upload(S, to, f.name, new Uint8Array(await f.arrayBuffer()), $('mode').value);
      if (!r.ok) return say($('sendmsg'), 'Rejected: ' + r.error, true);
      say($('sendmsg'), 'Sent as file #' + r.id);
      $('pipe').textContent = ['1. SHA-256 of plaintext:\n   ' + r.sha256, '2. Hash signed with your RSA-2048 key (RSA-PSS)',
        '3. AES-256-' + $('mode').value + ' encrypted, ' + r.ctBytes + ' bytes. First bytes the server sees:\n   ' + r.ctPreview,
        '4. AES key wrapped with ' + to + "'s RSA public key (RSA-OAEP)", '5. Uploaded: ciphertext + wrapped key + hash + signature'].join('\n');
      refresh();
    } catch (e) { say($('sendmsg'), e.message, true); }
  };

  async function refresh() {
    const tb = $('rows'); tb.replaceChildren();
    for (const f of await SC.list(S)) {
      const tr = tb.insertRow();
      [f.id, f.filename, f.sender + ' \u2192 ' + f.recipient, 'AES-256-' + f.mode].forEach(v => tr.insertCell().textContent = v);
      const c = tr.insertCell(), a = tr.insertCell();
      if (f.recipient === S.user) {
        const v = await SC.verifyRecord(S, await SC.fetchRecord(S, f.id));
        c.append(chip(v.verdict.toUpperCase(), v.verdict === 'Verified')); c.append(document.createTextNode(' ' + v.reason));
        const b = document.createElement('button'); b.textContent = 'Download'; b.onclick = () => download(f.id); a.append(b);
      } else {
        c.append(chip(f.storage === 'Intact' ? 'STORAGE INTACT' : 'STORAGE MODIFIED', f.storage === 'Intact'), chip(f.signature === 'Valid' ? 'SIG VALID' : 'SIG INVALID', f.signature === 'Valid'));
      }
    }
  }
  async function download(id) {
    const v = await SC.verifyRecord(S, await SC.fetchRecord(S, id));
    if (v.verdict !== 'Verified') return say($('dlmsg'), 'BLOCKED - ' + v.verdict + ': ' + v.reason, true);   // never hand over unverified data
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([v.plaintext])); a.download = v.filename; a.click();
    say($('dlmsg'), 'Verified and saved: ' + v.filename);
  }
  $('refresh').onclick = refresh;
})();
