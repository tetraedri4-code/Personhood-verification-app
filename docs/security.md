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
- **Each token opens one door**: evaluation and administration tokens are separate, at least 24
  characters, compared in constant time, and must differ. (The shared peer token of the first version
  is gone: operators sign.)
- **Deals are checked**: against the dealer's commitments, against the dealer's published verification
  key in a reshare, and across receivers before commit. A forged deal (tested) aborts the round.
- **The group key cannot change in a reshare**: every receiver recomputes it.
- **Shares on disk** are written to a temporary file with mode 0600 and renamed; a damaged share file
  stops the operator instead of starting it empty.
- **Plain http is refused** by the issuer's client, the coordinator and the dealers except on loopback.

What remains open for the threshold service is listed in [uniqueness.md](uniqueness.md) §4.

### Review of recovery, re-checks and the operator rounds, 16 November 2026

This change added the two-year re-check, backups, replacement of the secret, identity keys for the
uniqueness operators and a round protocol without a coordinator. Rows 12 and 13 above describe steps
(`discard`, `finalize`) that no longer exist: operators now erase old shares themselves once every
receiver has confirmed its new one, and a stalled round erases nothing.

The review was repeated until a pass found nothing with a reasonable fix: five passes, each a fresh
read of every new handler and message with the question "who controls this input, and what do they
gain", followed by fixes and tests.

**Pass 1**

| # | Problem | What an attacker could do | Fix | Test |
|---|---|---|---|---|
| 15 | A receiver that complained about a bad deal revealed its Diffie–Hellman value for whatever point E the dealer had sent | A cheating dealer that had seen an honest dealer's ciphertext (on the network) could resend that E in its own deal, provoke the complaint, and decrypt the honest dealer's sub-share from the opening | The dealer must prove it knows the exponent of E, bound to round, dealer and receiver. A receiver never raises its key on a ciphertext without that proof; such a deal convicts its dealer as it stands | `sign_seal_open`, `complaints_are_checked_by_everyone`, `two_faced_dealers_and_lying_receivers_are_named` |
| 16 | A dealer that showed different commitments to different receivers, or a receiver that sent a made-up "ready" hash, ended the round with nobody named | Stop every refresh and key generation for free, without being identified | Ready messages carry the dealers' signed commits. Two signatures of one dealer on different commits convict the dealer; a hash the sender's own evidence does not explain convicts the sender | same |
| 17 | An operator that found such a conflict failed the round before telling the others | The other operators waited until the timeout and never saw the evidence | It sends its own ready message, with its evidence, before stopping | same |
| 18 | The round id was a 128-bit hash of the spec | With about 2^64 work, two different specs with one id: administrators would approve one and operators run another | The id is the full SHA-256 | `complaints_are_checked_by_everyone` (id covers the spec) |
| 19 | The guardian key alone could refuse a waiting replacement | Whoever stole the phone could refuse its owner's replacement again and again and keep the stolen secret for good | Refusing takes a re-check: eID and old secret together. The guardian-key veto was removed | `replacement_without_the_guardian_key_waits_and_can_be_refused`, `replacing_the_secret` |
| 20 | Like proofs did not require a secret past probation | With replacement, a person could replace the secret and like every post again at once, each time | The like statement now proves that the secret was certified at least nine months ago | `replacement_with_the_guardian_key`, `replacing_the_secret` |
| 21 | The holder accepted any quarter end as the new expiry of a renewed or re-checked credential | The issuer could give one person an unusual expiry and recognise them by it later | The holder refuses an expiry other than the end of the current or the next quarter, and a re-check month other than the current one | covered by the renewal and re-check tests |
| 22 | Backup writes shared the lock that serialises changes to enrolment records | Anyone uploading backups could slow re-checks and replacements | Backups have their own lock | `backup_storage_rules` |

**Pass 2**

| # | Problem | What an attacker could do | Fix | Test |
|---|---|---|---|---|
| 23 | `pop holder restore` took the paper code only as a command-line argument | The code, which is as good as the secret, ended up in the shell history and the process list | Without an argument the command asks for the code | manual |

**Pass 3**

| # | Problem | What an attacker could do | Fix | Test |
|---|---|---|---|---|
| 24 | The app updated its backup right after every binding and unbinding | The backup host can tell whose a backup is (through the ticket). An update at the moment of a binding, next to the public list's new entry, told it which account that person had just bound | The backup is updated only after renewal, re-check and replacement; bindings reach it with the next renewal | `recheck_backup_and_restore_keep_the_same_person` |
| 25 | `replace_wait_days` was unchecked | A typo in the configuration (a huge number) wrapped the date arithmetic and made waits end at once | The issuer refuses values above ten years at start | start-up check |

**Pass 4**

| # | Problem | What an attacker could do | Fix | Test |
|---|---|---|---|---|
| 26 | A reshare could be written that left some holders of the old epoch out, with nothing said | Those operators keep their old shares; with enough of them the old sharing stays usable, which defeats the refresh | The command warns and names them; the documentation says to list every reachable holder as a dealer (a dealer that is not a receiver erases at the end) | `holders_left_out` in `d_survives_refresh_and_operator_changes` |
| 27 | A round spec could spell a key in upper-case hex | Deals are compared with the spec's text, so an honest dealer's correct deal would have looked wrong to a newcomer and the dealer been named | Keys in a spec must be in canonical form | `complaints_are_checked_by_everyone` |

**Pass 5** found nothing new with a reasonable fix. What it weighed and left is in "Known and not
fixed" below and in [recovery.md](recovery.md) §4 and [uniqueness.md](uniqueness.md) §4.

Checked and found sound in this change:

- **A login serves one purpose.** A session opened for a re-check cannot finish an enrolment or a
  replacement, and so on (tested). Enrolment needs a person without a record; re-check and replacement
  need one with a record.
- **A re-check proof is bound** to the session, the handle and the month it shows. Tested: another
  session, a wrong month, a plain renewal proof, another person's login.
- **Replacement never leaves two live secrets.** The old handle is revoked before the record changes;
  record changes are serialised; a claim works once; a blind request bound to another token is refused.
- **The new secret cannot be steered by the issuer**: it is drawn on the device and signed blindly, as
  at enrolment.
- **Backups**: the server stores ciphertext under an id it cannot connect to the code; the three
  derived values are independent; a tampered or wrongly keyed backup is refused; ids, sizes and
  characters are checked before anything is stored; a ticket pays for one backup (tested).
- **Operator messages** are signed over the round id, the sender and the exact bytes; an operator
  accepts them only for a round its own administrator approved, and only from the identity key that
  round names. A message in another operator's name is refused (tested).
- **A complaint cannot frame an honest dealer.** It needs the dealer's own signatures on a commit and a
  deal that do not fit together, for this round and this receiver. Tested with the right evidence from
  the wrong complainer, an opening for another message and a self-made deal.
- **Nothing is revealed before every dealer has committed**, and no share is erased before every
  receiver has confirmed its new one on disk.

### Review of syncing only changes, 19 November 2026

The directory's list and like table, and the issuer's revocation list, are now synced: a reader keeps
what it has and asks only for what changed after a change number (see [data-usage.md](data-usage.md)).
Three passes; the third found nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 28 | Reading the list right after a change number was taken but before the change was stored | A reader would skip that change for good: a badge missing, or a withdrawn one still shown | Writers take the number and store the change under the write lock; a reader takes that lock for a moment before reading, so every number it is given is complete | `readers_download_only_changes` |
| 29 | A reader whose numbers came from another store (the directory was reset or moved) | Its old claims would stay until their lease ran out | Every answer names the store; a reader sends the name back, and a different one gets the whole list | same |
| 30 | Moving the platform check out of the write lock had put it before the replay check | A replayed public proof would make the directory query the platform again each time | The proof's nonce is used up first, then the platform is asked | existing replay tests |
| 31 | A public re-check of an account rewrote the claim even when nothing changed | Anyone could make every reader download claims again, at will; a slow check could also overwrite a renewal made meanwhile | Only the result of the check is taken over, and only a real change gets a new number | `readers_download_only_changes` |

Checked and found sound in this change: the holder's rebuilt revocation tree must match the issuer's
root whatever its cache held (a stale or damaged cache means one full download, never a wrong tree);
the holder asks from a multiple of 64, so where it asks from says little about when it last asked;
the issuer keeps the order of revocations across restarts; compression is used only on public answers
(the directory, and the issuer's revocation list), so it cannot leak a secret as in the BREACH attack;
the extension ignores a `__proto__` key and anything but whole numbers in counts. Left as is: the
extension sends its exact change number, which tells the directory roughly when that browser last
synced. The browser's address tells it more, which is what relays are for (design §4.7).

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
   with the issuer too. The threshold service has limits of its own ([uniqueness.md](uniqueness.md) §4).
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
    operators do limit evaluations per minute.) Some issuer endpoints that need no login scan the
    record table (`/v1/revoke`, `/v1/replace/claim`, `/v1/replace/pending`).
11. **Recovery has edges** ([recovery.md](recovery.md) §4): during the 90-day wait a stolen phone keeps
    working; a replaced secret can like old posts again after its probation; whoever holds the eID and
    the current secret together wins every dispute; the backup host can link a backup to an enrolment
    record.
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
