// Pairing this computer for a while, for likes without the app on it (docs/pairing.md). The same
// format as crates/pop-protocol/src/mailbox.rs: nine words of POP_WORDS, PBKDF2-HMAC-SHA256 (600 000
// iterations, salt "pop-pairing-v1"), then HKDF-SHA256 for the mailbox id and two keys; likes are padded
// to 512 bytes and sealed with AES-256-GCM. Needs words.js first. Works in the service worker and in Node.
const PopPairing = (() => {
  const WORDS = typeof POP_WORDS !== "undefined" ? POP_WORDS : require("./words.js").POP_WORDS;
  const ITERATIONS = 600_000;
  const COUNT = 9;
  const PLAIN = 512;
  const te = new TextEncoder();
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
  const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  function generate() {
    const v = crypto.getRandomValues(new Uint16Array(COUNT));
    // 1024 divides 65536: the low ten bits are uniform
    return [...v].map((x) => WORDS[x & 1023]).join(" ");
  }

  async function derive(words, iterations = ITERATIONS) {
    const base = await crypto.subtle.importKey("raw", te.encode(words), "PBKDF2", false, ["deriveBits"]);
    const seed = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: te.encode("pop-pairing-v1"), iterations }, base, 256);
    const ikm = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
    const part = async (info) => hex(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: te.encode(info) }, ikm, 256));
    return { mailbox: await part("pop-pairing-v1 mailbox"), enc: await part("pop-pairing-v1 enc"), auth: await part("pop-pairing-v1 auth") };
  }

  async function endTag(keys, endMs) {
    const k = await crypto.subtle.importKey("raw", unhex(keys.auth), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return hex(await crypto.subtle.sign("HMAC", k, te.encode(`end|${endMs}`)));
  }

  // One like for the mailbox: the item, and the hash of the deletion code inside it.
  async function seal(keys, platform, post, at) {
    const d = random(32);
    const body = te.encode(JSON.stringify({ platform, post, at, d: hex(d) }));
    if (body.length > PLAIN) throw new Error("like too long");
    const plain = new Uint8Array(PLAIN).fill(0x20);
    plain.set(body);
    const k = await crypto.subtle.importKey("raw", unhex(keys.enc), "AES-GCM", false, ["encrypt"]);
    const iv = random(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(`pop-pairing-v1 item|${keys.mailbox}`) }, k, plain);
    return { item: hex(iv) + hex(ct), dh: hex(await crypto.subtle.digest("SHA-256", d)) };
  }

  return { generate, derive, endTag, seal, ITERATIONS };
})();
if (typeof module !== "undefined") module.exports = { PopPairing };
