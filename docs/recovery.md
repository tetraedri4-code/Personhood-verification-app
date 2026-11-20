# Re-check and recovery

Besides the quarterly renewal, these things can happen to a credential after enrolment:

| | When | What the person needs | What changes |
|---|---|---|---|
| **Identity re-check** | every two years | eID login + the app | nothing: same secret, same pseudonyms, same badges |
| **Restore a backup** (level 1) | phone lost or replaced | the paper code | nothing: the same secret on a new device |
| **Replace the secret** (level 2) | no backup, or the secret was stolen | eID login (+ the old guardian key, to skip the wait) | new secret, new pseudonyms, forty weeks of probation; the old secret is revoked |
| **"It wasn't me"** (theft report, §4) | someone enrolled with your identity | eID login | the other secret is revoked at once and you get a new one that counts after a week; the other side can block it for 90 days with its app and the eID (quickly once in two years; otherwise it waits like a replacement) |

All three are in the holder core (`crates/pop-holder/src/recovery.rs`) and the issuer
(`crates/pop-issuer/src/recovery.rs`, `backup.rs`). The interface between them is in
`crates/pop-protocol/src/api.rs`.

```sh
pop holder recheck            # two-year re-check
pop holder backup             # make a backup, print the paper code
pop holder restore            # asks for the code (or: restore <code>)
pop holder replace            # replace the secret after an eID login
pop holder replace --not-me   # the same, reporting that someone else enrolled with your identity
pop holder claim              # collect a replacement that had to wait
pop holder veto               # refuse a replacement, or lift a suspension (asks you to log in)
pop holder status             # shows the re-check date, warns of a waiting replacement or a suspension
```

`pop demo` runs a re-check, a backup with restore, a waiting replacement and a theft report (steps 9
to 12).

**Status: proposed change to the design, not folded.** First enrolments without probation, theft
reports with suspension, the alarm cutoff and the two-year rule for uncontested reports (§4) were agreed
for the prototype on 19 November 2026; the same day, the first report in two years was changed to give
the new secret at once, with a week's probation and 90 days in which the replaced secret can block it. These rules are not in design v2 yet; folding them into the design
waits for its author's word.

## 1. The two-year re-check

A credential carries the month of its owner's last identity check. The renewal proof only passes while
that month is less than 24 months old (plus a hidden grace of one to four months, drawn by the holder,
so that the date a credential stops renewing does not single out its enrolment month). Without a
re-check a credential stops renewing after about two years and runs out one or two quarters later.

What the re-check buys: a person who died, emigrated or lost their eID stops counting; a credential
that was sold or stolen stops unless the real person keeps cooperating every two years; and every
enrolment record is touched at least every two years, which is what moves records to a new uniqueness
key ([uniqueness.md](uniqueness.md) §2).

Flow:

1. `POST /v1/enrol/start` with `{"purpose": "recheck"}`. The person logs in; the issuer finds the
   person's enrolment record and shows the 6-digit code.
2. The holder makes a renewal proof that also **shows the revocation handle and the month of the last
   check**, bound to the session. `POST /v1/recheck`.
3. The issuer checks that the handle is the one in the record of the person who logged in, verifies the
   proof, and signs the same hidden attributes with the new month and a new expiry.

The issuer learns nothing new: it gave that handle to that record at enrolment. The secret and all
pseudonyms stay hidden and unchanged. Someone else's login cannot re-check your credential, and your
login cannot re-check someone else's (tested both ways).

The re-check must happen while the credential can still renew: within 24 months (plus grace) of the last
check, and within 12 months of its expiry. After that the way back is a replacement (§3).

## 2. Backup with a paper code (level 1)

`pop holder backup` encrypts the credential, the guardian key and the list of bound accounts, uploads
the ciphertext and prints a code of 26 characters (130 bits) such as `5BGD7-BFPKK-J1WXY-VJVYF-1395T-V`.
The person writes it on paper. The app does not keep the code.

- Three independent values are derived from the code with SHA-256: the backup's id, a write key and
  the encryption key. The server sees the id and a hash of the write key. It cannot read the backup
  and cannot guess the code (2^130 tries).
- Encryption is ChaCha20-Poly1305 with a random nonce. The plaintext is padded to a multiple of 4 kB,
  so the size says little about how many accounts are bound.
- The app keeps the id and the two keys, and silently updates the backup after each renewal, re-check
  and replacement. It does **not** update it when an account is bound or a like is reported: the
  backup host can know whose backup it is (below), and an update at that moment would point at the
  account. A new binding reaches the backup with the next renewal. A backup that missed updates still
  restores for about a year (it renews itself after the restore); accounts bound since then are bound
  again with one command and get the same code.
- `pop holder backup` again makes a new code and deletes the backup under the old one. Do that if the
  paper may have been seen.
- `pop holder revoke` deletes the backup.

`pop holder restore` on a device without a credential asks for the code, fetches and decrypts the
backup. It is the same secret: pseudonyms, badges and like tags are unchanged, and a person does not
count twice by restoring onto two devices.

**Who may create a backup.** Storage is not free, so a new backup needs a one-time ticket. The issuer
hands one out with every enrolment, re-check and replacement. Overwriting or deleting needs the write
key instead; deleting gives a ticket back.

**The paper code is as strong as the phone.** Whoever has it can restore the secret and use it
alongside you. If you think someone has, replace the secret (§3): the backup holds the guardian key, so
the replacement is immediate, and it revokes the copied secret.

**Hosting.** The two backup routes (`POST /v1/backup`, `GET /v1/backup/{id}`) are plain blob storage.
They live in the issuer process only because the prototype has no other always-on server. Because the
ticket was handed out at an identity check, the host can link a backup's id to an enrolment record,
and then sees when that backup is updated, which is when that person renewed. It learns nothing else
(not the secret, not a pseudonym). Put the routes on a host run by someone else to cut that link; the
only state they share with the issuer is the ticket table.

## 3. Replacing the secret (level 2)

For a person with no backup, or whose secret was copied. It starts with an eID login
(`{"purpose": "replace"}`); the page the issuer shows after login says in capitals that the secret is
about to be replaced. Then `POST /v1/replace` with a commitment to a **new** secret and a new guardian
key.

**With the old guardian key** (the wallet still has it, typically after restoring a backup): the
request carries a signature of the old guardian key, and the issuer acts at once. It signs the new
secret blindly, revokes the old handle and stores the new guardian key.

**Without it** (new phone, no backup): the eID alone asks, and the eID alone is what a thief of bank
credentials would have too. So the request **waits** (`policy.replace_wait_days` in the issuer configuration,
default 90):

- The issuer publishes the request in `GET /v1/replace/pending` under an id that only the holder of
  the old handle recognises. The old app looks there (`pop holder status`, `pop holder serve`; a
  phone app would at every start) and warns its owner.
- The owner **refuses** by doing a re-check with the old app (`pop holder veto`). That takes the eID
  and the old secret together, and cancels the request. The guardian key alone refuses nothing: a
  thief who has the phone but not the eID cannot keep its owner from replacing the secret.
- After the wait, `pop holder claim` collects the new credential (within a further 90 days). Only then
  is the old handle revoked.
- A newer request takes the place of an older one and starts the wait again.

**In both cases the new secret starts over:**

- Its probation runs forty weeks from the Monday of the week it is issued (`policy.probation_days`), about
  nine months, before its badges are counted and before it can report likes. This is what makes a stolen
  eID login worth little: each new secret can like every post again. The one exception is the first
  theft report in two years (§4).
- It has new pseudonyms. Accounts must be bound again; the old badges run out with their leases.
- At most one replacement per 30 days per person.

Who can do what:

| Attacker has | Can they take over? | Can they lock the owner out? |
|---|---|---|
| the phone (secret + guardian key), not the eID | uses the secret until the owner replaces it; cannot replace it | no: cannot refuse the owner's replacement (it takes the eID). The owner waits 90 days, or restores a backup and replaces at once |
| the eID, not the phone | with a plain request, only if the owner ignores the app's warning for 90 days, and then in probation. With "it wasn't me" while the two-year allowance is unused, at once, counting after a week, until the owner blocks it (§4) | the owner refuses each request, lifts each suspension, or blocks the reported replacement, with a re-check |
| the paper code, not the eID | restores and uses the secret alongside the owner | no: the owner replaces at once (guardian key) |
| the eID and the phone, or the eID and the paper code | yes | yes, until the eID is blocked at the bank. That is two of the person's factors |

## 4. "It wasn't me": theft reports, suspension and the alarm

**First enrolments count at once.** A secret's γ (`certified`) is the Monday of the week it was
issued; proofs show γ ≤ cutoff, and without an alarm the cutoff is today. There is no rollout window: a
backdated γ would escape the alarm below.

**Theft is noticed at enrolment.** Someone who enrols with a stolen eID login takes the identity's only
place. When the real person enrols later, the issuer refuses (`AlreadyEnrolled`), and the app tells them
what that means: either they enrolled before on another device, or their eID has been used by someone
else. In the second case the app points to [reset-eid/](reset-eid/README.md) (served by the holder app at
`/help/reset-eid`, and linked from the extension's options when a suspension shows): close the eID
with its provider, report the crime to the police, get new eID means, and only then come back.

**The report.** `pop holder replace --not-me` is a replacement request (§3) with `report_theft: true`
and no guardian signature (a report with one is refused: whoever holds that key enrolled the secret).
The issuer then

- **suspends** the enrolled secret at once: its handle goes on the revocation list, so it can no longer
  renew, bind or like. The suspended secret's app shows it (`pop holder status`, `serve`, the extension).
- **counts** the report in this week's public total (`GET /v1/reports`), at most once per person per 30
  days.
- **the first report in two years** (`policy.fresh_replacement_interval_days`, 730) gets the new secret at
  once. It counts after a week (`policy.report_probation_days`, rounded up to a Monday so the date tells only
  the week), and the enrolled secret is revoked. For 90 days (`policy.contest_days`) the replaced secret can
  **block** it (below).
- a later report within the two years suspends the enrolled secret and waits like any other request
  (90 days), and the new secret then has the usual forty weeks of probation.

**Blocking a reported replacement, or lifting a suspension.** Whoever holds the replaced or suspended
secret and can log in with the eID does it with a re-check (`pop holder veto`). The renewal proof
inside the re-check is made against the revocation list as it was just before the handle was added; the
issuer checks that root, gives the same secret a new handle (signed by the witness key; the commitment
is updated without the holder's help), and cancels any waiting request. A block also revokes the secret
the report gave, whatever has happened to it since: replacing it again with its guardian key, or
revoking it, does not end the 90 days. If it is the thief who blocks or lifts, the real person's eID is
still not safe: they secure it and report again.

**Why a week, and when the allowance comes back.** If a thief made the report, the owner is most likely
active, sees the warning in their app and blocks within the week, before any of the thief's likes
count. Likes cannot be linked to the secret that made them, so likes counted before a block stay
counted: what a false report gains is at most the likes between the end of the week and the block.

A block **before the replacement starts counting** gives the two-year allowance back: that secret
never counted, so nothing was gained. This matters to an owner whose own report a thief blocked (the
thief holding the old phone and the eID): once the owner has secured the eID, they can report again
and be served at once (after the 30 days between replacements). A thief who reports again gains
nothing either, because the owner blocks again before the week ends.

A block **after** that day does not give the allowance back, so a thief who keeps access to the eID
cannot get a counting secret every month by reporting from a device of their own; their next reports
wait 90 days and then nine months, and the owner blocks them. (Osama's decision, 20 November 2026.)
Each new secret can like every post again, so the allowance also bounds what a report about one's own
secret gains: one more like on a post, once in two years.

**The alarm.** Reports are counted per week and published with the rule. A week is high if it has at
least 20 reports and at least three times the median of the twelve weeks before it (configurable:
`policy.alarm`). While any of the last four weeks is high, the **alarm cutoff** is
28 days before the Monday of the earliest high week (`policy.alarm.reach_days`), and proofs show γ ≤ cutoff
instead of γ ≤ today. So secrets enrolled from about a month before a wave of reports stop counting
until the alarm ends; older secrets are not touched. The cutoff is in `/v1/params`, the holder proves
against it and names it in each request, and the directory refuses a proof made under another cutoff
(409; the app fetches the parameters again). Badges bound after the cutoff stop counting while the
alarm is on, unless proved again under it (`BindingEntry::counts`, mirrored in the extension).

## 5. Limits

- **Stolen phone, no backup: the thief keeps using the secret during the 90 days.** An immediate freeze
  on eID login alone would let an eID thief switch off anybody's badge at will. Revoking at once takes
  the guardian key (`pop holder revoke`), which is in the backup.
- **A replaced secret can like the same posts again after its probation.** Like tags come from the
  secret, so one person can count twice on an old post, once per replacement, nine or more months
  apart.
- **An eID thief can suspend an enrolled person's secret** by reporting "it wasn't me", again after each
  lift. Each round costs the thief an eID login; the owner lifts it with a re-check and should secure
  the eID. The design's in-person desk is for this case.
- **An eID thief's first report works at once.** Its secret counts after a week, until the owner
  blocks it; likes counted before the block stay (they cannot be linked to the secret). If the owner does
  not open the app for 90 days, the thief keeps the identity, and the owner's two-year allowance is used
  up. A real app would notify the owner (push message, e-mail from the issuer); the prototype warns only
  when the app runs.
- **Whoever starts a report last wins the waiting slot.** A newer request replaces an older one, so an
  eID thief can overwrite the real person's report until the eID is secured.
- **The issuer counts reports and computes the alarm.** The counts and the rule are public, so anyone
  can recompute the cutoff from the counts, but not check the counts themselves: an oversight body
  should audit them against the records.
- **Colluding enrolled people can raise the alarm** by reporting themselves (20 in a week by default,
  more as the median grows). It costs each of them a suspended secret, which they can lift. The effect
  is that enrolments of the last month or so stop counting for four weeks. Real thresholds belong to the
  operator and should be set from data.
- **Likes reported before an alarm stay counted.** The alarm stops new likes and new bindings by recent
  secrets; it does not remove counts already made.
- **Each proof under an alarm shows one more bit:** that its secret is older than the cutoff.
- **A suspended secret that expires can no longer be lifted** (a re-check needs a credential that can
  still renew); its owner then replaces it, with probation.
- **Sold eID logins are not caught by reports**: a person who sells their login does not report it.
- **Whoever holds both the eID and the current secret wins every dispute.** The design sends such cases
  to a desk with an in-person check; the prototype has no desk.
- **If the answer to a replacement is lost on the way** (network failure after the issuer acted), the
  old secret is revoked and the new one never arrived. The person asks again after 30 days. A real
  service would make the request repeatable for a day.
- **The re-check needs a credential that can still renew.** Too late means replacement and probation.
- **The backup host can link a backup to an enrolment record** through the ticket (§2).
- **Unauthenticated endpoints** (`/v1/replace/claim`, `/v1/replace/pending`, `/v1/revoke`) go through
  lookup tables, not a scan of the records, but have no rate limit of their own. Rate-limit them at the
  proxy. `/v1/replace/pending` returns every waiting request.
- **One issuer process.** Changes to a record are serialised by a lock inside the process; several
  issuer processes over one database need compare-and-swap there.
- **`pop holder backup` prints the code to the terminal.** A phone app would show it once on screen.
