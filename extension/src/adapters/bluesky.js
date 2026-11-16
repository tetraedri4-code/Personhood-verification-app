// Adapter for bsky.app. The selectors follow the data-testid attributes of Bluesky's open-source web
// client (feedItem-by-<handle>, postThreadItem-by-<handle>, likeBtn, profileHeaderDescription).
// NOT yet tested against the live site: check them when you first load the extension there.
(() => {
  const POST_RE = /^\/profile\/([^/]+)\/post\/([A-Za-z0-9._~:-]+)/;
  const PROFILE_RE = /^\/profile\/([^/]+)\/?$/;
  const didCache = new Map();

  async function didOf(actor, helpers) {
    if (actor.startsWith("did:")) return actor;
    const h = actor.toLowerCase();
    const known = helpers.byHandle.get(h);
    if (known && known.length) return known[0].account_id;
    if (didCache.has(h)) return didCache.get(h);
    // asks Bluesky's own public API, which already knows what this browser is reading
    const r = await helpers.send({ type: "bluesky-resolve", handle: h });
    const did = r && typeof r.did === "string" && r.did.startsWith("did:") ? r.did : null;
    didCache.set(h, did);
    return did;
  }

  globalThis.__pop.register({
    id: "bluesky",
    matches: (loc) => loc.hostname === "bsky.app",

    findAccounts: (root) => {
      const out = [];
      for (const a of root.querySelectorAll('a[href^="/profile/"]')) {
        const m = PROFILE_RE.exec(a.getAttribute("href"));
        // name links only: avatar links have no text, and one badge per feed item is enough
        if (!m || !a.textContent.trim() || a.textContent.trim().startsWith("@")) continue;
        const actor = decodeURIComponent(m[1]);
        out.push(actor.startsWith("did:") ? { el: a, accountId: actor } : { el: a, handle: actor });
      }
      const name = root.querySelector('[data-testid="profileHeaderDisplayName"]');
      const pm = PROFILE_RE.exec(location.pathname);
      if (name && pm) {
        const actor = decodeURIComponent(pm[1]);
        out.push(actor.startsWith("did:") ? { el: name, accountId: actor } : { el: name, handle: actor });
      }
      return out;
    },

    findPosts: (root) => {
      const out = [];
      for (const el of root.querySelectorAll('[data-testid^="feedItem-by-"], [data-testid^="postThreadItem-by-"]')) {
        const link = [...el.querySelectorAll('a[href*="/post/"]')].find((a) => POST_RE.test(a.getAttribute("href")));
        // the focused post of a thread has no link to itself: use the page address
        const raw = link ? link.getAttribute("href") : POST_RE.test(location.pathname) ? location.pathname : null;
        const likeButton = el.querySelector('[data-testid="likeBtn"]');
        if (raw && likeButton) out.push({ el, raw, likeButton });
      }
      return out;
    },

    profile: (root) => {
      const m = PROFILE_RE.exec(location.pathname);
      const bio = root.querySelector('[data-testid="profileHeaderDescription"]');
      if (!m || !bio) return null;
      const actor = decodeURIComponent(m[1]);
      const p = actor.startsWith("did:") ? { accountId: actor } : { handle: actor };
      return { ...p, bioText: bio.textContent };
    },

    // Bluesky marks a liked post in the button's accessible label ("Unlike (...)").
    isLiked: (btn) => /^unlike/i.test(btn.getAttribute("aria-label") || ""),

    // Same id as the Rust adapter: at://<did>/app.bsky.feed.post/<rkey>
    canonicalPostId: async (raw, helpers) => {
      const m = POST_RE.exec(raw);
      if (!m) return null;
      const did = await didOf(decodeURIComponent(m[1]), helpers);
      return did ? `at://${did}/app.bsky.feed.post/${m[2]}` : null;
    },
  });
})();
