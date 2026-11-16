// Adapter for the local mock feed. The smallest complete adapter: copy it for a new platform.
// An adapter only reads the page. It must not fetch anything and must not change the page.
globalThis.__pop.register({
  id: "mockfeed",
  matches: (loc) => /^(127\.0\.0\.1|localhost)$/.test(loc.hostname) && !!document.querySelector('[data-pop-platform="mockfeed"]'),

  // Elements that name an account; a badge goes right after `el`.
  findAccounts: (root) =>
    [...root.querySelectorAll("[data-pop-account]")].map((el) => ({ el, accountId: el.dataset.popAccount, handle: el.dataset.popHandle })),

  // Posts: `raw` is whatever canonicalPostId needs; `likeButton` is watched for clicks.
  findPosts: (root) =>
    [...root.querySelectorAll("[data-pop-post]")].map((el) => ({ el, raw: el.dataset.popPost, likeButton: el.querySelector("[data-pop-like]") })),

  // The profile shown on this page, if any, with the text where a binding code may appear.
  profile: (root) => {
    const p = root.querySelector("[data-pop-profile]");
    if (!p) return null;
    const bio = p.querySelector("[data-pop-bio]");
    return { accountId: p.dataset.popProfile, handle: p.dataset.popHandle, bioText: bio ? bio.textContent : "" };
  },

  isLiked: (btn) => btn.classList.contains("liked"),

  // Must give the same id as the Rust adapter's canonical_post_id.
  canonicalPostId: async (raw) => (/^p\d+$/.test(raw) ? raw : null),
});
