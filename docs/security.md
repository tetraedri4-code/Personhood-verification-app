# Security

This is a research prototype. It has had one internal review (below) and no independent audit. Do not
enrol real people on it without one.

## Review of 15–16 November 2026

Method: a read of every request handler, proof verifier call and trust boundary, asking for each input
who controls it and what they gain; `cargo audit` over the dependencies; then a test for each fix.

### Found and fixed

| # | Problem | What an attacker could do | Fix | Test |
|---|---|---|---|---|
| 1 | The enrolment session id was sent through the browser as the OpenID Connect `state` | The identity provider, or anyone who saw the redirect, could finish the enrolment with their own secret and take the person's one credential | A separate random `state`; the session id is known only to the holder app | `the_redirect_state_is_not_the_session` |
| 2 | Nothing tied the browser that logged in to the device that enrols | Send a victim a login link; when they log in with their bank ID, the attacker's device gets their credential | The issuer shows a 6-digit code after login, the app must send it; five wrong tries end the session | `enrolment_needs_the_code_from_the_browser` |
| 3 | Binding and withdrawal proofs could be replayed; binding records are public | Re-submit a published proof the same day, e.g. to bring back a badge its owner withdrew | Each proof's nonce is accepted once | `directory_rejects_replays_...` |
| 4 | A new claim on an account replaced the existing one | Any enrolled person could name a victim's account and make the victim's badge disappear | Claims are kept side by side per pseudonym; the code on the account decides which is real | `a_false_claim_cannot_remove_someone_elses_badge` |
| 5 | The directory accepted any platform name and any post id | An enrolled person could fill the store, and everyone's downloaded table, with made-up entries | Only platforms the directory was started with; only post ids in the platform's canonical form; length limits | `directory_rejects_replays_...` |
| 6 | The ID token's signature algorithm was taken from the token without restriction | Depends on the provider's keys; a classic source of token forgery | Only asymmetric algorithms; provider endpoints must be https (http only on loopback) | compile-time list in `oidc.rs` |
| 7 | Enrolment sessions never expired and kept the deduplication key | Unbounded growth; a lasting record of who tried to enrol and when | 15-minute lifetime, deleted when enrolment finishes, cap on open sessions | covered by the enrolment tests |
| 8 | The claimed handle was stored as submitted | A claim could show a misleading handle next to a real account id | The platform's own spelling of the handle is stored; a handle that resolves to another account is refused | `directory_rejects_replays_...` |
| 9 | `legogroth16`'s default features pulled in a WebAssembly runtime with two advisories (RUSTSEC-2026-0344, RUSTSEC-2026-0186) | Not reachable from this code, but 200 unused crates of attack surface | Feature switched off; the runtime is no longer built | `cargo audit` |

### Checked and found sound

- **Proof verification.** Points are subgroup-checked on decoding; identity elements are rejected where
  they would make the pairing equations trivial; vector lengths are bounded before allocation; a
  malformed proof that makes the engine panic is caught and counted as invalid. Every public value of a
  statement is in the Fiat–Shamir challenge. Tested: a proof fails for another account, another context,
  another post, another day's root, and with a swapped pseudonym.
- **Blind issuance.** The commitment comes with a proof of knowledge bound to the session, so it cannot
  be replayed into another session. The holder checks the signature, the witness signature and the
  attribute grids before accepting a credential.
- **One enrolment per person** rests on an atomic insert keyed by the deduplication hash; identity codes
  are normalised first (case, spaces).
- **The holder's local API** needs the pairing token in a header on every call, compares it in constant
  time, answers cross-origin preflights only for extension origins and listens on loopback only.
  Tested from a web page in a real browser and with raw requests.
- **The extension** writes page and directory data into the DOM only as text; accepts messages only from
  its own scripts; sends the pairing token only to loopback; talks to the directory only over https or
  loopback; downloads whole lists instead of asking about single accounts or posts; reports likes only
  after the person switches that on.
- **The Bluesky adapter** writes only into the account whose DID matches the login, keeps the other
  profile fields, and uses a conditional write. The app password is read from the environment and never
  leaves the device.
- **HTML output** of the mock identity provider, the mock feed and the issuer's callback page escapes
  everything that comes from a request.

### Known and not fixed

These are limits of the prototype, in rough order of weight:

1. **Trusted setup by one party.** With LegoGroth16 the issuer generates the proving keys and could forge
   proofs. Use Bulletproofs or run a ceremony ([crypto.md](crypto.md)).
2. **One operator holds everything**: issuer key, witness key and uniqueness key in one process. The
   design splits these so that no single party can mint people or test who is enrolled
   ([real-servers.md](real-servers.md) §3).
3. **The secret is in a plain file** (`wallet.json`, mode 0600). Anything running as the same user can
   copy it and become that person. A real app wraps it with a hardware key.
4. **Not constant-time.** Timing side channels on the proving device are possible.
5. **No relays.** The directory sees the address and time of every binding and like report, which can
   link them to a person despite the cryptography. Enrolment followed at once by a binding is linkable
   by timing, the more so with few users.
6. **A removed code keeps its badge.** The directory checks the code when a claim is made or re-checked,
   and an extension remembers a code it saw. If an account is sold or hijacked and the code removed, the
   badge can stay until the lease ends (nine months). Periodic re-checks and a shorter memory in the
   extension would narrow this.
7. **A platform, or anyone who controls an account's page as you see it, can fake the "code seen"
   signal for that account.** The proof still has to exist in the directory, so this needs an enrolled
   person's claim on that account as well.
8. **Like reports cannot be limited per person**, because they are unlinkable. An enrolled person can
   add one count each to any number of well-formed post ids, including ones that do not exist. They
   cannot add more than one count to any post.
9. **A count is self-reported.** It says an enrolled person's app reported a like, not that the like
   exists on the platform.
10. **No rate limiting in the services.** Put it in the reverse proxy.
11. **No recovery.** A lost wallet is a lost identity in this prototype: the person cannot enrol again.
12. **The mock services have no security at all** by design: the mock identity provider logs anyone in
    as anyone, the mock feed has no passwords. They listen on loopback. Never expose them.
13. **The 6-digit enrolment code** stops link-based hijacking unless the victim also reads the code to
    the attacker. A phone app should replace it with an app link.

### Dependencies

`cargo audit` reports no vulnerabilities with the one exception recorded, with its reason, in
`.cargo/audit.toml`. It also warns that three crates used by arkworks 0.4 are unmaintained
(`derivative`, `paste`, `clear_on_drop`); moving to arkworks 0.5 would clear those and is worth doing
with the audit.

## Reporting a problem

Open an issue in the repository, or for anything exploitable contact the maintainer privately first.
