// Oblivious HTTP client (RFC 9458) for the background worker: a request to the directory goes, encrypted
// to the directory's gateway key, through a relay run by someone else. The relay sees this computer's
// address but not the request; the directory sees the request but only the relay's address.
// Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (RFC 9180), messages in known-length
// binary HTTP (RFC 9292). Everything with WebCrypto; no library.
(function (root) {
  "use strict";
  const subtle = root.crypto.subtle;
  const te = new TextEncoder();
  const KEM = 0x0020, KDF = 0x0001, AEAD = 0x0001;
  const NK = 16, NN = 12, NH = 32, NPK = 32;
  const EMPTY = new Uint8Array(0);

  const cat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let i = 0;
    for (const p of parts) (out.set(p, i), (i += p.length));
    return out;
  };
  const u16 = (v) => Uint8Array.of(v >> 8, v & 0xff);

  // HKDF-SHA256 from HMAC. An empty salt is the same HMAC key as HashLen zero bytes (RFC 5869 §2.2).
  async function hmac(key, data) {
    const k = await subtle.importKey("raw", key.length ? key : new Uint8Array(NH), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", k, data));
  }
  async function expand(prk, info, len) {
    let t = EMPTY, out = EMPTY;
    for (let i = 1; out.length < len; i++) out = cat(out, (t = await hmac(prk, cat(t, info, Uint8Array.of(i)))));
    return out.slice(0, len);
  }
  const V1 = te.encode("HPKE-v1");
  const SUITE_KEM = cat(te.encode("KEM"), u16(KEM));
  const SUITE = cat(te.encode("HPKE"), u16(KEM), u16(KDF), u16(AEAD));
  const lExtract = (suite, salt, label, ikm) => hmac(salt, cat(V1, suite, te.encode(label), ikm));
  const lExpand = (suite, prk, label, info, len) => expand(prk, cat(u16(len), V1, suite, te.encode(label), info), len);

  async function aead(op, key, nonce, data) {
    const k = await subtle.importKey("raw", key, "AES-GCM", false, [op]);
    return new Uint8Array(await subtle[op]({ name: "AES-GCM", iv: nonce }, k, data));
  }

  // HPKE base mode, sender side, one message (sequence number 0)
  async function setupSender(pkR, info) {
    const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const enc = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
    const pub = await subtle.importKey("raw", pkR, { name: "X25519" }, false, []);
    const dh = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, eph.privateKey, 256));
    const shared = await lExpand(SUITE_KEM, await lExtract(SUITE_KEM, EMPTY, "eae_prk", dh), "shared_secret", cat(enc, pkR), 32);
    const ctx = cat(Uint8Array.of(0), await lExtract(SUITE, EMPTY, "psk_id_hash", EMPTY), await lExtract(SUITE, EMPTY, "info_hash", info));
    const secret = await lExtract(SUITE, shared, "secret", EMPTY);
    return {
      enc,
      key: await lExpand(SUITE, secret, "key", ctx, NK),
      nonce: await lExpand(SUITE, secret, "base_nonce", ctx, NN),
      exporter: await lExpand(SUITE, secret, "exp", ctx, NH),
    };
  }

  // application/ohttp-keys: a list of (length, key configuration); take the first one in our suite
  function pickKey(list) {
    for (let i = 0; i + 2 <= list.length; ) {
      const len = (list[i] << 8) | list[i + 1];
      const c = list.subarray(i + 2, i + 2 + len);
      i += 2 + len;
      if (c.length < 3 + NPK + 2 || ((c[1] << 8) | c[2]) !== KEM) continue;
      const pk = c.slice(3, 3 + NPK);
      const n = (c[3 + NPK] << 8) | c[4 + NPK];
      for (let j = 5 + NPK; j + 4 <= 5 + NPK + n && j + 4 <= c.length; j += 4) {
        if (((c[j] << 8) | c[j + 1]) === KDF && ((c[j + 2] << 8) | c[j + 3]) === AEAD) return { id: c[0], pk };
      }
    }
    throw new Error("relay: no usable gateway key");
  }

  // binary HTTP, known length
  function varint(n) {
    if (n < 0x40) return Uint8Array.of(n);
    if (n < 0x4000) return Uint8Array.of(0x40 | (n >> 8), n & 0xff);
    if (n < 0x40000000) return Uint8Array.of(0x80 | (n >>> 24), (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
    throw new Error("too long");
  }
  const vec = (b) => cat(varint(b.length), b);
  function encodeRequest(method, url, body) {
    const u = new URL(url);
    const fields = body ? cat(vec(te.encode("content-type")), vec(te.encode("application/json"))) : EMPTY;
    return cat(varint(0), vec(te.encode(method)), vec(te.encode(u.protocol.slice(0, -1))), vec(te.encode(u.host)), vec(te.encode(u.pathname + u.search)), vec(fields), vec(body || EMPTY), varint(0));
  }
  function decodeResponse(b) {
    let i = 0;
    const vi = () => {
      if (i >= b.length) throw new Error("relay: truncated answer");
      const first = b[i], len = 1 << (first >> 6);
      if (i + len > b.length) throw new Error("relay: truncated answer");
      let v = first & 0x3f;
      for (let k = 1; k < len; k++) v = v * 256 + b[i + k];
      i += len;
      return v;
    };
    const bytes = () => {
      if (i >= b.length) return EMPTY; // trailing parts may be left out
      const n = vi();
      if (i + n > b.length) throw new Error("relay: truncated answer");
      return b.subarray((i += n) - n, i);
    };
    const fields = (sec) => {
      const out = {};
      for (let j = 0; j < sec.length; ) {
        const take = () => {
          const first = sec[j], len = 1 << (first >> 6);
          let n = first & 0x3f;
          for (let k = 1; k < len; k++) n = n * 256 + sec[j + k];
          j += len;
          return sec.subarray((j += n) - n, j);
        };
        const name = new TextDecoder().decode(take()).toLowerCase();
        out[name] = new TextDecoder().decode(take());
      }
      return out;
    };
    if (vi() !== 1) throw new Error("relay: not a known-length response");
    let status = vi();
    while (status >= 100 && status < 200) (bytes(), (status = vi()));
    const headers = fields(bytes());
    return { status, headers, body: bytes() };
  }

  let sent = 0;
  const keys = new Map(); // relay address -> key list (the same for everyone: fetched through the relay)
  const BAD_KEY = "ohttp: cannot decrypt (key changed?)";

  async function fetchKeys(relay) {
    const r = await fetch(`${relay}/keys`, { credentials: "omit", cache: "no-store" });
    if (!r.ok || r.headers.get("content-type") !== "application/ohttp-keys") throw new Error(`relay key: ${r.status}`);
    const k = new Uint8Array(await r.arrayBuffer());
    keys.set(relay, k);
    return k;
  }

  // Send one request through `relay` (e.g. https://relay.example/directory). `url` is the address on the
  // server; only its path and host go inside the encrypted request. Returns { status, headers, body }.
  async function request(relay, method, url, body) {
    const plain = encodeRequest(method, url, body ? te.encode(body) : null);
    for (let attempt = 0; attempt < 2; attempt++) {
      const list = attempt === 0 && keys.has(relay) ? keys.get(relay) : await fetchKeys(relay);
      const { id, pk } = pickKey(list);
      const hdr = cat(Uint8Array.of(id), u16(KEM), u16(KDF), u16(AEAD));
      const s = await setupSender(pk, cat(te.encode("message/bhttp request"), Uint8Array.of(0), hdr));
      const ct = await aead("encrypt", s.key, s.nonce, plain);
      const r = await fetch(relay, { method: "POST", credentials: "omit", cache: "no-store", headers: { "content-type": "message/ohttp-req" }, body: cat(hdr, s.enc, ct) });
      const res = new Uint8Array(await r.arrayBuffer());
      sent++;
      if (r.status === 400 && attempt === 0 && new TextDecoder().decode(res) === BAD_KEY) continue;
      if (!r.ok || r.headers.get("content-type") !== "message/ohttp-res") throw new Error(`relay: ${r.status}`);
      if (res.length < NK + 16) throw new Error("relay: short answer");
      // RFC 9458 §4.4: key and nonce for the answer from the request's context and the answer's nonce
      const secret = await lExpand(SUITE, s.exporter, "sec", te.encode("message/bhttp response"), Math.max(NN, NK));
      const prk = await hmac(cat(s.enc, res.subarray(0, Math.max(NN, NK))), secret);
      const inner = await aead("decrypt", await expand(prk, te.encode("key"), NK), await expand(prk, te.encode("nonce"), NN), res.subarray(Math.max(NN, NK)));
      return decodeResponse(inner);
    }
    throw new Error("relay: the gateway's key keeps changing");
  }

  root.PopOhttp = { request, get sent() { return sent; } };
})(globalThis);
