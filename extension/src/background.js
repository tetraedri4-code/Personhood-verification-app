// Background worker: the only part of the extension that talks to the network.
//  * directory (public, no credentials): the list of verified accounts and the table of counts, kept in
//    chrome.storage.local and brought up to date with only the changes since the last download
//  * holder app on 127.0.0.1 (pairing token): report a like, read which posts this person liked
//  * with a relay set, every directory request goes through it, encrypted to the directory (ohttp.js):
//    the directory does not see this computer's address, the relay does not see the request
// Settings live in chrome.storage.local.
importScripts("ohttp.js");
const DEFAULTS = { directoryUrl: "http://127.0.0.1:4003", relayUrl: "", holderUrl: "http://127.0.0.1:4010", token: "", reportLikes: false };
const TTL_MS = 60_000;
const cache = new Map();

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) };
}

// Only loopback and https servers are accepted, so a mistyped setting cannot send data in clear text.
function base(url) {
  const u = new URL(url);
  const loopback = u.hostname === "127.0.0.1" || u.hostname === "localhost";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) throw new Error("server address must be https, or http on this computer");
  return u.origin;
}

async function cached(key, load) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.value;
  const value = await load();
  cache.set(key, { at: Date.now(), value });
  return value;
}

// A relay address keeps its path (one relay can serve several servers under different paths).
function relayAddr(url) {
  if (!url) return null;
  const u = new URL(url);
  const loopback = u.hostname === "127.0.0.1" || u.hostname === "localhost";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) throw new Error("relay address must be https, or http on this computer");
  if (u.search || u.hash) throw new Error("relay address must not have a query");
  return u.origin + u.pathname.replace(/\/+$/, "");
}

// A GET to the directory: through the relay when one is set, else straight.
async function dirJson(s, url) {
  const relay = relayAddr(s.relayUrl);
  if (!relay) return getJson(url);
  const r = await PopOhttp.request(relay, "GET", url);
  if (r.status < 200 || r.status >= 300) throw new Error(`${r.status}`);
  return JSON.parse(new TextDecoder().decode(r.body));
}

async function getJson(url, init) {
  const r = await fetch(url, { credentials: "omit", cache: "no-store", ...init });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

async function holder(s, path, body) {
  // the holder app must be on this computer: the token must never go anywhere else
  const u = new URL(s.holderUrl);
  if (u.protocol !== "http:" || !(u.hostname === "127.0.0.1" || u.hostname === "localhost")) throw new Error("holder app must be on this computer");
  if (!s.token) throw new Error("no pairing token set");
  return getJson(u.origin + path, {
    method: body ? "POST" : "GET",
    headers: { "content-type": "application/json", "x-pop-token": s.token },
    body: body ? JSON.stringify(body) : undefined,
  });
}

const PLATFORM_RE = /^[a-z0-9-]{1,32}$/;

// The worker is stopped when idle, so the synced copy lives in storage, not in memory.
// Per directory and platform: { at, today, listSeq, entries: {account|nym: entry}, countSeq, counts }.
const SYNC_VERSION = 1;
const syncing = new Map();

async function synced(s, dir, platform) {
  const key = `sync|${dir}|${platform}`;
  let st = (await chrome.storage.local.get(key))[key];
  if (!st || st.v !== SYNC_VERSION) st = { v: SYNC_VERSION, at: 0, today: 0, instance: "", listSeq: 0, entries: {}, countSeq: 0, counts: {} };
  if (Date.now() - st.at < TTL_MS) return st;
  // one sync at a time per platform, however many tabs ask
  if (!syncing.has(key)) {
    syncing.set(key, (async () => {
      try {
        const inst = encodeURIComponent(st.instance || "");
        const list = await dirJson(s, `${dir}/v1/bindings?platform=${platform}&since=${st.listSeq}&instance=${inst}`);
        if (list.full) st.entries = {};
        for (const g of list.gone || []) delete st.entries[`${g.account_id}|${g.nym}`];
        for (const e of list.entries || []) st.entries[`${e.account_id}|${e.nym}`] = e;
        st.listSeq = list.seq;
        st.today = list.today;
        st.alarm = Number.isInteger(list.alarm_cutoff) ? list.alarm_cutoff : null;
        // claims whose lease ran out are not announced as gone: drop them here
        for (const [k, e] of Object.entries(st.entries)) if (e.lease_until < list.today) delete st.entries[k];
        const table = await dirJson(s, `${dir}/v1/likes/table?platform=${platform}&since=${st.countSeq}&instance=${inst}`);
        if (table.full) st.counts = {};
        for (const [k, n] of Object.entries(table.counts || {})) if (k !== "__proto__" && Number.isSafeInteger(n)) st.counts[k] = n;
        st.countSeq = table.seq;
        st.instance = list.instance;
        st.at = Date.now();
        await chrome.storage.local.set({ [key]: st });
        return st;
      } finally {
        syncing.delete(key);
      }
    })());
  }
  return syncing.get(key);
}

async function forgetCounts(dir, platform) {
  // after a like, look again at once instead of waiting for the next minute
  const key = `sync|${dir}|${platform}`;
  const st = (await chrome.storage.local.get(key))[key];
  if (st) {
    st.at = 0;
    await chrome.storage.local.set({ [key]: st });
  }
}

async function handle(msg) {
  const s = await settings();
  if (msg.type === "data") {
    if (!PLATFORM_RE.test(msg.platform)) throw new Error("bad platform");
    const dir = base(s.directoryUrl);
    const st = await synced(s, dir, msg.platform);
    const seen = (await chrome.storage.local.get("seen")).seen || {};
    const entries = Object.values(st.entries).sort((a, b) => (a.account_id < b.account_id ? -1 : a.account_id > b.account_id ? 1 : 0));
    return { settings: { reportLikes: !!s.reportLikes }, today: st.today, alarm: st.alarm ?? null, entries, counts: st.counts, seen: seen[msg.platform] || {} };
  }
  if (msg.type === "seen") {
    const all = (await chrome.storage.local.get("seen")).seen || {};
    (all[msg.platform] ||= {})[msg.accountId] = msg.code;
    await chrome.storage.local.set({ seen: all });
    return {};
  }
  if (msg.type === "like") {
    if (!s.reportLikes) throw new Error("like reporting is off");
    const r = await holder(s, "/v1/like", { platform: msg.platform, post: msg.post });
    await forgetCounts(base(s.directoryUrl), msg.platform);
    const mine = (await chrome.storage.local.get("liked")).liked || {};
    const arr = (mine[msg.platform] ||= []);
    if (!arr.includes(msg.post)) arr.push(msg.post);
    await chrome.storage.local.set({ liked: mine });
    return r;
  }
  if (msg.type === "status") {
    return { liked: (await chrome.storage.local.get("liked")).liked || {} };
  }
  if (msg.type === "holder-status") {
    return holder(s, "/v1/status");
  }
  if (msg.type === "bluesky-resolve") {
    if (!/^[a-z0-9.-]{3,253}$/.test(msg.handle)) throw new Error("bad handle");
    return cached(`did|${msg.handle}`, () =>
      getJson(`https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(msg.handle)}`));
  }
  throw new Error("unknown message");
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  // messages are accepted only from this extension's own scripts
  if (sender.id !== chrome.runtime.id) return false;
  handle(msg).then(reply, (e) => reply({ error: String(e && e.message ? e.message : e) }));
  return true;
});
