# Security

This is a research prototype. It has had internal reviews (below) and no independent audit. Do not
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

### Review of the uniqueness service, 16 November 2026

Same method, over the key versioning in the issuer and the new threshold service (`pop-uniqueness`):
every operator endpoint, every message of a round, and what each token holder can do.

| # | Problem | What an attacker could do | Fix | Test |
|---|---|---|---|---|
| 10 | Operator endpoints read and parsed the request before checking the token | Anyone who can reach an operator could make it parse input and learn the request format from the errors | The token check runs first, before the body is read | `tokens_and_rate_limit` |
| 11 | An operator that repeated its answer made the issuer's combination step panic | One faulty or hostile operator could stop all enrolments | One answer per operator and epoch is used; the rest is ignored | `repeated_answers_are_ignored` |
| 12 | A round whose commit reached only some operators left them at different epochs with no way forward | A crash or one failing operator at the wrong moment blocked every later refresh | Receivers that committed discard the new epoch; the round is undone automatically | `a_failed_commit_is_undone` |
| 13 | `finalize` erased whatever was older than the epoch it was given | A wrong epoch number erased every share of the key, which cannot be undone | An operator refuses to erase its last share unless told it is leaving; the coordinator first verifies the new epoch from public data | `rounds_are_all_or_nothing` |
| 14 | The issuer took the threshold of an epoch from the largest value any operator stated | One operator stating a huge threshold made the issuer skip a working epoch | The value most operators state is used; a wrong one only costs a failed check | `a_lying_operator_cannot_change_d` |

Checked and found sound:

- **A wrong d cannot be produced.** The combined result is checked against the pinned group key with a
  pairing. Tested with a lying operator, a key the operators do not hold, and too few operators.
- **A missing answer is never "not enrolled".** If any live key version cannot be evaluated the issuer
  answers 503. If records exist under a key the service does not hold, the issuer does not start.
- **Operators never see identities**: the request is blinded with a fresh random scalar.
- **Each token opens one door**: evaluation, administration and peer tokens are separate, at least 24
  characters, compared in constant time, and must differ.
- **Deals are checked**: against the dealer's commitments, against the dealer's published verification
  key in a reshare, and across receivers before commit. A forged deal (tested) aborts the round.
- **The group key cannot change in a reshare**: every receiver recomputes it.
- **Shares on disk** are written to a temporary file with mode 0600 and renamed; a damaged share file
  stops the operator instead of starting it empty.
- **Plain http is refused** by the issuer's client, the coordinator and the dealers except on loopback.

What remains open for the threshold service is listed in [uniqueness.md](uniqueness.md) §4.

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
2. **One operator holds the issuer key and the witness key** in one process. The design splits these
   so that no single party can mint people ([real-servers.md](real-servers.md) §3). The uniqueness key
   can be split among operators (threshold service), but in the default single-operator mode it sits
   with the issuer too. The threshold service has limits of its own: simple key generation without a
   complaint phase, one coordinator holding the admin tokens, a shared peer token, sub-shares protected
   by TLS only ([uniqueness.md](uniqueness.md) §4).
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
10. **No rate limiting in the issuer and the directory.** Put it in the reverse proxy. (The uniqueness
    operators do limit evaluations per minute.)
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
