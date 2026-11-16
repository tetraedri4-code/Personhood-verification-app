# Adding a platform

A platform needs two small adapters, one for each side:

| | Where | Language | What it does |
|---|---|---|---|
| App side | a new crate `crates/pop-platform-<id>` | Rust | resolves accounts, publishes the code, canonical post ids |
| Browser side | a new file `extension/src/adapters/<id>.js` | JavaScript | finds accounts, posts and like buttons in the page |

Nothing else changes: not the crypto, not the holder, not the servers. Pick an id of lower-case letters
(`mastodon`, `x`); it becomes part of the context id `pop:ctx:v1:<id>`, so it must never change once
people have bound accounts.

Start by copying the mock feed adapters. They are the smallest complete examples:
`crates/pop-platform-mockfeed/src/lib.rs` (about 130 lines) and
`extension/src/adapters/mockfeed.js` (about 30 lines).

## App side: the `Platform` trait

`crates/pop-protocol/src/platform.rs`:

```rust
#[async_trait]
pub trait Platform: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    async fn resolve_account(&self, handle_or_url: &str) -> Result<AccountRef, PlatformError>;
    async fn publish_code(&self, account: &AccountRef, code: &str, placement: CodePlacement) -> Result<(), PlatformError>;
    async fn remove_code(&self, account: &AccountRef, code: &str) -> Result<(), PlatformError>;
    async fn public_texts(&self, account: &AccountRef) -> Result<Vec<String>, PlatformError>;
    async fn canonical_post_id(&self, raw: &str) -> Result<String, PlatformError>;
}
```

What each method must guarantee:

- **`resolve_account`** returns an `account_id` that never changes for the account (a numeric id, a
  DID), and the current handle. The proof is bound to the id, so a renamed account keeps its badge. If
  the platform gives you no way to look an id up, return `PlatformError::Unsupported` and let the person
  supply the id; the extension must then find the same id in the page.
- **`publish_code`** writes only into the account the credentials belong to. Check that the logged-in
  account's id equals `account.account_id` and return `NoCredentials` otherwise (see the Bluesky
  adapter). With no credentials configured, return `NoCredentials`: the holder then tells the person to
  paste the code by hand, which is the normal case on closed platforms.
- **`public_texts`** is used by the directory to confirm a code server-side. Implement it only through
  an interface the platform offers for this (Bluesky's public API). On platforms whose terms forbid
  automated reading, return `Unsupported`: badges then appear once a viewer's extension has seen the code
  on the profile page. Never work around rate limits, logins or captchas (voluntary-app report §2.3,
  §2.4). Return only text written by the account itself; the Bluesky adapter drops reposts.
- **`canonical_post_id`** must map every way of naming a post to one string, and map that string to
  itself (the directory rejects ids that are not a fixed point). Two people liking the same post must get
  the same id, or their likes are counted on different posts.

Then:

1. Add the crate to `members` and `[workspace.dependencies]` in the root `Cargo.toml`.
2. Build it in `platforms()` in `crates/pop-cli/src/wiring.rs` and add its options to `PlatformArgs` in
   `main.rs`. This is the only existing code you touch.
3. Start the directory with the platform enabled. A directory accepts bindings and likes only for
   platforms it was started with.

Test against a fake server, as `pop-platform-bluesky` does: no test should need the real platform.

## Browser side: the extension adapter

Register an object with these members (`extension/src/core.js` calls them):

```js
globalThis.__pop.register({
  id: "<id>",                                   // same id as the Rust adapter
  matches: (location) => boolean,               // is this page the platform?
  findAccounts: (root) => [{ el, accountId?, handle? }],   // a badge is drawn right after el
  findPosts: (root) => [{ el, raw, likeButton, countAnchor? }],
  profile: (root) => ({ accountId?, handle?, bioText }) | null,
  isLiked: (likeButton) => boolean,             // after a click: is the post now liked?
  canonicalPostId: async (raw, helpers) => string | null,
});
```

- Give `accountId` where the page has it; otherwise give `handle` and the core matches by handle.
- `canonicalPostId` must return exactly what the Rust adapter returns for the same post.
- An adapter only reads the page. It does not fetch, does not change the page and does not store
  anything. Network access goes through `helpers.send` to the background worker, and only for the
  platform's own public API (see `bluesky-resolve`), never to tell the directory what the person reads.

Then add the file and the site to `manifest.json`: the site under `content_scripts.matches`, the file
in `content_scripts.js` before `src/main.js`, and any API host under `host_permissions`.

Selectors on real sites change without notice. Prefer attributes meant for automation (`data-testid`,
`aria-label`) to class names, and expect to maintain the adapter.

## What a platform must offer

- A stable account id you can read.
- A bio or posts where the account holder can put 19 characters.
- For like counts: a like button the extension can see, and post ids in the page.

Not needed: any cooperation from the platform, any API key, or reading other people's likes.

## Before adding a closed platform

Read its current terms on browser extensions and automated access (the voluntary-app report could not:
§2.3 and §7). The design keeps to reading what the logged-in person is shown anyway and writing only
into their own account, but a platform can still object, delete codes or suspend accounts.
