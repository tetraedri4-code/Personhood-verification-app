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
fixed" below and in [recovery.md](recovery.md) §5 and [uniqueness.md](uniqueness.md) §4.

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

### Review of theft reports, suspension and the alarm, 19 November 2026

First enrolments without probation, "it wasn't me" reports that suspend a secret, the lift by re-check,
the alarm cutoff and the help page ([recovery.md](recovery.md) §4). Three passes; the third found
nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 32 | Proofs against the issuer's previous revocation root were taken until the next revocation, and the directory trusted its cached roots until an unknown root arrived | A secret suspended (or revoked) a moment ago could keep renewing, binding and liking against the root from before, for days in a quiet period. "Suspended at once" would not have held | The issuer offers the previous root for two minutes after a change (`policy.previous_root_grace_secs`); the directory fetches the roots again when they are older than 30 seconds | `a_theft_report_suspends_and_a_recheck_lifts_it`, `it_wasnt_me_suspends_...` |
| 33 | The rollout window (`rollout_certified`) backdated every first enrolment to the launch | Enrolments made during the window, which is when stolen logins would be used, could never be reached by an alarm | Removed: γ is always the Monday of the week of issue. First enrolments count at once anyway | `many_reports_raise_the_alarm_...` |

Checked and found sound: a lift needs the record's current handle, a suspension on it, and a proof
against the exact revocation list before the handle (a permanently revoked secret, or one replaced
since, cannot use it); the new handle is drawn and signed by the issuer and can only take the holder's
existing commitment; a report with a guardian signature is refused, so the key holder cannot launder a
plain replacement into an uncontested report; reports count once per person per 30 days and need an
enrolled identity; the uncontested-report rule is checked at claim time against the latest request, and
a re-check or a guardian replacement in between clears the suspension; the directory checks the alarm
cutoff named in a proof against the issuer's and asks the issuer again at most every five seconds; the
help page is a fixed text compiled into the app, served without scripts and not frameable. Left as is,
and listed in [recovery.md](recovery.md) §5: repeated suspensions by an eID thief, a dormant owner
losing an uncontested report, the issuer as the only counter of reports, and collusion to raise the
alarm. The help page needs no pairing token, so a web page can tell that the holder app runs on a
computer; the 401 of the other endpoints told it before, and browsers' private-network rules block it.

### Review of the eID help pages for every member state, 19 November 2026

The help page became one page per member state and language, with a country search and a language
choice ([reset-eid/](reset-eid/README.md), `pop-holder/src/help.rs`). Two passes; the second found
nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 34 | Markdown was rendered with raw HTML passed through | With 61 pages, many translated, a stray or slipped-in tag (an `<iframe>`, a form, a link with odd markup) would have become part of the page; scripts were already blocked by the CSP | Raw HTML in the text is shown as text; every link in the pages and source lists must be `https://` | `raw_html_in_a_page_is_shown_as_text`, `links_in_pages_are_web_links` |
| 35 | The page relied on `X-Frame-Options` only, and had no `nosniff` | Older browsers that ignore the header could frame it | CSP `frame-ancestors 'none'` and `X-Content-Type-Options: nosniff` added | `the_help_page_is_public_...` |

Checked and found sound: nothing from the request is written into a page (an unknown country gives a
fixed message, the language is picked from known codes), the redirect after a search is built only from
a known country code and language, so it cannot point elsewhere; the search input is refused above 100
bytes before it is copied; forms may submit only to the app (`form-action 'self'`); the pages stay
outside the token check, as before, because they hold no personal data.

### Review of the quick replacement after a theft report, 19 November 2026

The first report in two years now gets the new secret at once, counting after a week, and the replaced
secret can block it for 90 days ([recovery.md](recovery.md) §4). Three passes; the third found
nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 36 | A re-check of a revoked enrolment was refused before the block was considered | Whoever made a false report could revoke their own new secret with its guardian key, and the owner could no longer block: the identity would stay revoked, and the owner would have to wait 90 days and nine months for a replacement | A block is checked first and works on a revoked record; it makes the record active again | `a_replacement_after_a_report_can_be_blocked_for_90_days_only` |
| 37 | A replacement with the guardian key (or any later replacement) would have cleared the time to block | The reporter could end the owner's 90 days after 30, by replacing their own new secret | The time to block survives later replacements; a block revokes whatever secret is current | `a_theft_report_replaces_at_once_and_the_replaced_secret_can_block_it` |

Checked and found sound: a block needs a login of the same person and a proof with the replaced
secret's own handle, against the revocation list as it was before that handle went on it; the block
ends after 90 days and is cleared then; a block does not give back the two-year allowance once the replacement has counted (one made
before then does, since nothing was gained; added 20 November), so a thief who keeps the eID gets at most
one counting quick replacement in two years, and later ones wait and have full probation; reports still count once per person per 30 days. Left as is: likes counted between the end
of the week and a block stay counted, because likes cannot be linked to the secret that made them.

### Review of the issuer's policy settings, 19 November 2026

Every number the rules chose is now a setting (`policy` in the issuer configuration, published at
`GET /v1/policy`; the badge lease is `pop directory --lease-days`). Two passes; the second found
nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 38 | Day settings had no upper bound once they became settings | A huge value would overflow the date sums (wrapping in a release build), so a wait or a block window could end at once, or a probation date fall outside the proofs' 16-bit range | Every day setting must be 1 to 3650 (the directory's lease 7 to 3650); rules between settings are checked too (whole-week probation, block window longer than the probation it guards, quick-replacement interval at least the block window) | `settings_that_break_a_rule_are_refused` |
| 39 | Unknown fields in the issuer configuration were ignored | The examples still carried `rollout_certified`, removed earlier; an operator setting `replace_wait_days` at the old place would have believed it applied | The configuration, the policy and the alarm rule refuse unknown fields; the examples are checked by a test | `the_example_configurations_parse` |

### Review of the issuer's lookup tables, 19 November 2026

`/v1/revoke`, `/v1/replace/claim` and `/v1/replace/pending` no longer read every enrolment record. Three
tables in the same store lead to the record: handle to record key, claim-token hash to record key, and
the keys of records with a waiting replacement (`crates/pop-issuer/src/index.rs`). They hold nothing the
records do not; every record write updates them; every lookup checks the record it reaches, so a stale
entry is ignored; the issuer rebuilds them at start. Two passes; the second found nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 40 | Moving a record to the newest uniqueness key (at login) did not hold the records lock (there before this change) | A claim timed to run during the thief's own login after a key change was written to the old key and deleted with it: the record kept the old handle and the waiting request, so the token could be claimed a second time, and the first new secret was never revoked, giving one person two working secrets | The move holds the same lock as revoke, re-check, replace and claim | none (a race); the lock is the one the other writers hold |

### Review of the Oblivious HTTP relay, 19 November 2026

Holder and extension requests can go through a relay to a gateway in front of the issuer and the
directory ([relay.md](relay.md)). Two passes; the second found nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 41 | The relay fetched the gateway's key again whenever a request could not be decrypted | Anyone, the server's operator included, could empty the relay's copy by sending garbage; a server doing so could give each client that fetched next a key of its own, and so recognise all its requests | The relay keeps a key at least ten minutes whatever the gateway answers | `the_relay_keeps_one_key_for_everyone_for_a_while` |
| 42 | The gateway would encrypt any answer up to 256 MB | Each request in flight holds about three copies: a few parallel requests for a large answer could exhaust memory | 32 MB cap (the largest answer today is under 2 MB) | none |

Checked and found sound: the gateway passes on only `content-type` and `accept` (so no
`accept-encoding`: no compression inside, and nothing of the sender's), refuses inner requests to its
own routes or to a full address, and refuses requests it cannot decrypt before they reach the server;
the relay forwards only to the gateways it is set up for (not an open proxy), sends only the body on,
and validates gateway names; both clients accept only https or loopback relay addresses and check the
content types; the answer is authenticated (AES-GCM) before the extension parses it; the extension's
HPKE code gives the same bytes as the Rust gateway expects (tested against it).

### Review of padding, the random wait before likes, and count buckets, 19 November 2026

Relay messages are padded to the issuer's size classes, holders wait a random time (issuer setting,
default up to 10 minutes) before proving and sending a like, and the extension fetches count buckets
for the posts on screen once a platform outgrows one bucket. Two passes; the second found nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 43 | A bucket request could name the same bucket many times | With one bucket for everything, a single request made the directory gather the whole table 64 times | Each bucket at most once per request | `count_buckets_partition_the_table` |
| 44 | Clicking like again on a post already liked or waiting queued another send | One more message through the relay for each click: harmless to the count, but more traffic tied to the click | Nothing more is sent for a post already liked or waiting | `holder_local_api_needs_the_pairing_token` |

Checked and found sound: the like proof is made after the wait, so it is against the revocation root
of that moment (a proof made before a ten-minute wait would be refused after a revocation); waiting
likes survive a restart of the holder app and are dropped (not retried forever) if refused; the
extension's own-like display is bounded by the count at the click plus one and expires; the size
classes a client adopts from an answer must pass the same bounds as the issuer's setting; padding is
zero bytes after the message, which both binary HTTP readers ignore; the JavaScript bucket hash is the
same as the directory's (the browser test checks counts in bucket mode).

Known and not fixed: **the directory chooses the bucket size**, and a dishonest one could make buckets
of one post. **A screen's set of buckets can point to the page:** ten posts of one profile fall into ten
buckets, and few other pages give the same set, so the directory can guess that someone viewed that
profile. Buckets hide single posts, not pages. Through a relay the directory does not learn who; without
one it learns the address. Use a relay.

### Review of the schedule for likes, 20 November 2026

The random wait before a like (up to ten minutes) is replaced by a schedule shared by everyone: a like
clicked in one window (issuer setting, default half an hour) is proved and sent at a random moment of
the next. Two passes; nothing to fix.

Checked and found sound: the send moment does not depend on when in its window the like was clicked
(test `a_like_goes_out_in_the_next_window_whenever_it_was_clicked`); each like still has its own proof,
so likes stay unlinkable; sends are spread over the window, so there is no spike at the marks; a like
whose window passed while the app was closed goes out in the window after the next start, revealing
nothing more; the setting is at most 12 hours, so the longest wait (two windows) stays within a day and
the extension's display of a waiting like stays bounded; the proof is still made at send time, against
that moment's revocation root and probation.

Found in the review and then fixed (Osama's suggestion): the windows followed the device's clock, so a
device whose clock is minutes off sent outside everyone else's windows and could be told apart. They now
follow the middle of the issuer's, the directory's and the relay's times; the device's clock votes only
without a relay (tests `one_lying_server_does_not_move_the_clock`,
`the_clock_learns_the_server_and_the_relay_time_through_the_relay`). Two of the three agreeing to lie
can still move an app's windows.

### Review of batch checking and the servers' clock, 20 November 2026

Like proofs can be checked in batches (`Scheme::verify_likes`, `Scheme::sieve_likes`, [crypto.md](crypto.md));
the like windows follow the middle of the issuer's, the directory's and the relay's times. Two passes;
the second found nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 45 | A malformed proof that made the checking code panic failed the whole sieve | One crafted proof would have sunk every true like in its batch | Each proof's own checks, and each combined check, catch a panic as a failure of that proof or set; halving then isolates it | `batch_check_accepts_good_likes_and_refuses_any_bad_one_*` |
| 46 | With many false proofs, halving costs more than checking each alone (about n log2 n) | Someone sending mostly false proofs could make the server work harder than without batches | Past a budget of 3n proofs' worth, the rest are checked one by one | same |

Checked and found sound: the random scalars come from the operating system's generator, so no prover
can make a false proof cancel out; LegoGroth16 proofs in one batch must share one key set; proofs that
fail their own (per-proof) checks never enter a combined check; a proof's parts swapped with another's,
a proof claimed for another post, or one from another issuer's credential are all caught (tests). The
server times come from the gateways inside the encryption, so the relay can neither read nor change
them, and the relay's own time from its answer; an unreadable date is ignored.

### Review of the batchable proof format and batch checking in the directory, 20 November 2026

Proofs now carry the Schnorr commitments instead of the challenge, the witness signature on the handle
is BBS instead of Pointcheval–Sanders, and the directory checks likes in batches ([crypto.md](crypto.md)).
Two passes; the second found nothing new.

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 47 | **Before this change, a proof without its SNARK part was accepted.** The verifier checked the Bulletproofs or LegoGroth16 proof only if one was present (`if let Some(..)`), and the challenge simply hashed an empty SNARK. Found by reading the code; not demonstrated with a forged proof | A person with a modified app could leave out the circuit, and with it the proof that the like tag and the pseudonym come from their secret: any number of likes on one post, any number of pseudonyms. Present since the first version | A proof must carry the SNARK of the configured proof system, or it is false | `batch_check_accepts_good_likes_and_refuses_any_bad_one_*` (all proofs go through the new check) |
| 48 | In the commitment form nothing is checked before the combined check, so any well-formed false proof reaches it | Anyone can send false proofs that cost the directory combined checks and halving | The halving budget (#46) bounds it: with many false proofs the cost is about that of checking each alone. The batch size also shrinks with the recent share of false proofs (16 to 256), and grows back as true proofs wash the share out | `likes_checked_in_one_batch_get_each_their_own_answer`, measured in crypto.md |

| 49 | A proof against a revocation root newer than the directory's last fetch was refused as stale when that fetch was under 2 s old | A holder who fetched the root right after a revocation was refused and had to prove again (two end-to-end tests failed by timing) | Such a request waits for the next allowed fetch (at most 2 s); one fetch at a time, so waiting requests do not all ask the issuer | `replacing_the_secret`, `recheck_backup_and_restore_keep_the_same_person` |

Checked and found sound: the challenge hashes the commitments with everything else, as before (standard
Fiat–Shamir with commitments); the two BBS equations, the Schnorr relations and the LegoGroth16 equation
each get their own random scalars; a proof must have as many commitments as relations and as many
responses as witnesses; the witness signature uses its own generators (`WITNESS_P1`, `WITNESS_H`), and
its relation shares the response for r with the credential's, so both sign the same handle; the directory's
batches never mix days, revocation roots or cutoffs; a like waits at most 50 ms for its batch; the queue
to the checker is bounded (4,096), so a flood makes senders wait instead of filling memory; witness keys
from before this change are refused with a message (they were PS keys).

### Review of pairing a computer without the app, 20 November 2026

A computer without the app is paired for a chosen period by nine words; its likes wait, encrypted, in a
mailbox until the app collects them and the person approves them ([pairing.md](pairing.md)). Two passes;
the second found only a point for the docs (likes left by whoever has the words are sent without asking
on a pairing with `auto`; pairing.md now says to use it only on one's own devices).

| # | Problem | Effect | Fix | Test |
|---|---|---|---|---|
| 50 | Anyone could open up to 100,000 mailboxes with 256 items each (about 30 GB) | Memory or disk exhaustion of the mailbox server | A cap on items over all mailboxes (200,000, about 250 MB); further deposits get 503 until collections free room | `close_limits_and_sweep` |
| 51 | The first version answered pairing messages (`pair-status` returns the words) from any of the extension's scripts, content scripts included | A content script runs inside a web page: a page that compromised its renderer could read the words and leave likes for the person to approve | Pairing messages are answered only for the extension's own pages (sender URL in the extension's origin). Found while writing; never pushed | extension e2e (pairing from the options page) |
| 52 | The content script reported a like on any click event on a like button, including `click()` called by the page's own script | A site could make the extension report likes the person never clicked (to the holder app, or now to the mailbox). Present since the first extension | Only trusted events (`event.isTrusted`) count | extension e2e (Playwright clicks are trusted) |
| 53 | A deposit in the same millisecond as a close was accepted (the check was `now > end`) | A computer could leave one more like right after being unpaired | A closed mailbox refuses every deposit | `a_paired_computer_leaves_likes_for_approval` |

Checked and found sound: the words give 90 bits, stretched by 600,000 PBKDF2 iterations, so the server,
which sees the mailbox id and the ciphertexts, cannot guess them; the id, encryption and tag keys are
separate HKDF outputs; AES-GCM nonces are random, and with at most 256 items per key a repeat is
negligible; every item is padded to 512 bytes, so lengths say nothing of the post; the additional data
binds an item to its mailbox; the end is vouched for by an HMAC the server cannot make, and the app
only lets it move earlier; anything the server reports as arriving after the end is dropped; a
deletion needs the code inside the item; the mailbox id travels only in POST bodies and is stored hashed;
collected likes are saved before they are deleted from the mailbox, and the last item number keeps them
from being collected twice; post ids with control characters are refused, so they cannot carry
terminal escapes into `pop holder pairings`; the extension keeps the words and the posts liked while
paired in session storage, which content scripts cannot read and which is dropped when the browser closes;
the Rust and JavaScript formats agree on fixed vectors also computed with Python.

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
5. **Relays are optional and do not delay.** Without one, the directory sees the address and time of
   every binding and like report, which can link them to a person despite the cryptography. With one
   ([relay.md](relay.md)) it sees no address, but still the time: enrolment followed at once by a
   binding is linkable by timing, the more so with few users. A server could give a different key in
   each ten-minute window and so tell apart clients that fetched it in different windows.
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
    operators do limit evaluations per minute.) The issuer reads every enrolment record twice at start
    (key versions, lookup tables).
11. **Recovery has edges** ([recovery.md](recovery.md) §5): during the 90-day wait a stolen phone keeps
    working; a replaced secret can like old posts again after its probation; whoever holds the eID and
    the current secret together wins every dispute; the backup host can link a backup to an enrolment
    record; an eID thief can suspend an owner's secret again and again; the issuer alone counts the
    theft reports that set the alarm.
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
