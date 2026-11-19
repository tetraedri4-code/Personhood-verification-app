// Platform-independent part of the content script. It knows nothing about any site's markup: adapters
// (src/adapters/*.js) find accounts and posts in the page and this file decides what to draw.
//
// Privacy rules this file keeps:
//  * It never asks a server about an account or a post. The background worker keeps the whole public
//    list of verified accounts (syncing only changes), and this file looks accounts up locally. For
//    counts it asks for the buckets of the posts on screen, each bucket holding many posts, in one
//    request per screen (or keeps the whole table while it is small).
//  * A like is reported only if the person switched reporting on in the options.
//  * Everything from the directory and from the page is treated as untrusted text: it reaches the DOM
//    only through textContent and title, never as HTML.
(() => {
  const adapters = [];
  const POP = (globalThis.__pop = {
    register(adapter) { adapters.push(adapter); },
    adapters,
    CODE_RE: /pop1-[a-km-np-z2-9]{4}-[a-km-np-z2-9]{4}-[a-km-np-z2-9]{4}/g,
  });

  const send = (msg) =>
    new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? { error: chrome.runtime.lastError.message } : r));
      } catch (e) {
        resolve({ error: String(e) });
      }
    });

  POP.start = async function start() {
    const adapter = adapters.find((a) => a.matches(location));
    if (!adapter) return;
    const state = { list: new Map(), byHandle: new Map(), counts: {}, mine: new Set(), seen: {}, settings: {}, today: 0 };

    async function refresh() {
      const r = await send({ type: "data", platform: adapter.id });
      if (!r || r.error) return;
      state.settings = r.settings;
      state.today = r.today;
      state.alarm = Number.isInteger(r.alarm) ? r.alarm : null;
      state.seen = r.seen || {};
      // an account can have several claims (anyone enrolled can name any account); keep them all
      state.list = new Map();
      state.byHandle = new Map();
      for (const e of r.entries) {
        const h = String(e.handle).toLowerCase();
        if (!state.list.has(e.account_id)) state.list.set(e.account_id, []);
        state.list.get(e.account_id).push(e);
        if (!state.byHandle.has(h)) state.byHandle.set(h, []);
        state.byHandle.get(h).push(e);
      }
    }

    // An entry earns a badge only once its code was actually seen on the account: by the directory
    // (where the platform has a public interface) or by this browser on the profile page.
    function confirmed(entry) {
      if (!entry || entry.lease_until < state.today) return false;
      return entry.code_seen_on != null || state.seen[entry.account_id] === entry.code;
    }

    // The claims on an account, and among them the one whose code was seen there (at most one counts).
    function claimsFor(acct) {
      if (acct.accountId) return state.list.get(acct.accountId) || [];
      return (acct.handle && state.byHandle.get(acct.handle.toLowerCase())) || [];
    }
    const entryFor = (acct) => claimsFor(acct).find(confirmed);

    // Same rule as BindingEntry::counts in the protocol: while an alarm is on, a claim counts if it
    // was made before the cutoff or proved again under this alarm.
    function countsNow(entry) {
      if (!entry.counted) return false;
      const a = state.alarm;
      return a == null || entry.bound_on < a || entry.proved_alarm === a;
    }

    function drawBadge(el, entry) {
      const next = el.nextElementSibling;
      const has = next && next.classList && next.classList.contains("pop-badge");
      if (!confirmed(entry)) {
        if (has) next.remove();
        return;
      }
      const b = has ? next : document.createElement("span");
      const counts = countsNow(entry);
      b.className = "pop-badge" + (counts ? "" : " pop-probation");
      b.textContent = "1";
      b.title = counts
        ? "One enrolled person runs this account (personhood prototype). This says nothing about who they are or whether they are trustworthy."
        : state.alarm != null && entry.counted
          ? "One enrolled person runs this account. Not counted while the alarm about stolen eID logins is on (recent enrolments are paused)."
          : "One enrolled person runs this account, with a secret still in probation (replaced less than nine months ago).";
      b.setAttribute("role", "img");
      b.setAttribute("aria-label", "one enrolled person");
      if (!has) el.insertAdjacentElement("afterend", b);
    }

    function drawCount(post, id) {
      const anchor = post.countAnchor || post.likeButton;
      if (!anchor) return;
      let c = anchor.parentElement.querySelector(":scope > .pop-count");
      if (!c) {
        c = document.createElement("span");
        anchor.insertAdjacentElement("afterend", c);
      }
      const n = Number(state.counts[id] || 0);
      const mine = state.mine.has(id);
      c.className = "pop-count" + (n === 0 ? " pop-zero" : "") + (mine ? " pop-mine" : "");
      c.textContent = `${n} verified`;
      c.title =
        `${n} enrolled ${n === 1 ? "person says" : "people say"} they liked this post. ` +
        "Counts people, not accounts, and only people who use this extension." +
        (mine ? " Your like is included." : "");
      c.dataset.popPost = id;
    }

    const hooked = new WeakSet();
    function hookLike(post, id) {
      const btn = post.likeButton;
      if (!btn || hooked.has(btn)) return;
      hooked.add(btn);
      btn.addEventListener("click", () => {
        if (!state.settings.reportLikes) return;
        // let the site handle the click first, then see whether the post is now liked
        setTimeout(async () => {
          if (!adapter.isLiked(btn)) return;
          const r = await send({ type: "like", platform: adapter.id, post: id, shown: state.mine.has(id) ? null : Number(state.counts[id] || 0) });
          if (r && !r.error) {
            // the holder app sends the like after a random wait; show it now
            if (!state.mine.has(id)) state.counts[id] = Number(state.counts[id] || 0) + 1;
            state.mine.add(id);
            scan();
          }
        }, 150);
      });
    }

    async function noteProfile() {
      const p = adapter.profile && adapter.profile(document);
      if (!p) return;
      const codes = (p.bioText || "").toLowerCase().match(POP.CODE_RE) || [];
      const entry = claimsFor(p).find((e) => codes.includes(e.code));
      if (entry && state.seen[entry.account_id] !== entry.code) {
        state.seen[entry.account_id] = entry.code;
        await send({ type: "seen", platform: adapter.id, accountId: entry.account_id, code: entry.code });
      }
    }

    let scanning = false, again = false;
    async function scan() {
      if (scanning) { again = true; return; }
      scanning = true;
      try {
        await noteProfile();
        for (const a of adapter.findAccounts(document)) drawBadge(a.el, entryFor(a));
        const found = [];
        for (const post of adapter.findPosts(document)) {
          const id = await adapter.canonicalPostId(post.raw, { byHandle: state.byHandle, send });
          if (id) found.push([post, id]);
        }
        // one request for the whole screen
        const r = found.length ? await send({ type: "counts", platform: adapter.id, posts: found.map(([, id]) => id) }) : null;
        if (r && r.counts) {
          for (const [id, n] of Object.entries(r.counts)) state.counts[id] = n;
        }
        for (const [post, id] of found) {
          hookLike(post, id);
          drawCount(post, id);
        }
      } catch (e) {
        console.debug("[pop] scan failed", e);
      } finally {
        scanning = false;
        if (again) { again = false; scan(); }
      }
    }

    await refresh();
    const mine = await send({ type: "status" });
    if (mine && mine.liked) state.mine = new Set(mine.liked[adapter.id] || []);
    await scan();
    let timer = null;
    new MutationObserver((muts) => {
      // ignore our own insertions
      if (muts.every((m) => [...m.addedNodes].every((n) => n.nodeType === 1 && /^pop-/.test(n.className || "")))) return;
      clearTimeout(timer);
      timer = setTimeout(scan, 250);
    }).observe(document.body, { childList: true, subtree: true });
    setInterval(async () => { await refresh(); scan(); }, 60_000);
  };
})();
