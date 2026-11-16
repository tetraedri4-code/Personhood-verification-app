# Re-check and recovery

Three things happen to a credential after enrolment besides the quarterly renewal:

| | When | What the person needs | What changes |
|---|---|---|---|
| **Identity re-check** | every two years | eID login + the app | nothing: same secret, same pseudonyms, same badges |
| **Restore a backup** (level 1) | phone lost or replaced | the paper code | nothing: the same secret on a new device |
| **Replace the secret** (level 2) | no backup, or the secret was stolen | eID login (+ the old guardian key, to skip the wait) | new secret, new pseudonyms, nine months of probation; the old secret is revoked |

All three are in the holder core (`crates/pop-holder/src/recovery.rs`) and the issuer
(`crates/pop-issuer/src/recovery.rs`, `backup.rs`). The interface between them is in
`crates/pop-protocol/src/api.rs`.

```sh
pop holder recheck            # two-year re-check
pop holder backup             # make a backup, print the paper code
pop holder restore            # asks for the code (or: restore <code>)
pop holder replace            # replace the secret after an eID login
pop holder claim              # collect a replacement that had to wait
pop holder veto               # refuse a replacement someone else asked for (asks you to log in)
pop holder status             # shows the re-check date, and warns of a waiting replacement
```

`pop demo` runs a re-check, a backup with restore, and a waiting replacement (steps 9 to 11).

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
credentials would have too. So the request **waits** (`replace_wait_days` in the issuer configuration,
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

- Its probation runs from the start of the **next** quarter, rollout window or not, so it is at least
  nine months before its badges are counted and before it can report likes. This is what makes a stolen
  eID login worth little, and it is why like proofs now require a secret that has passed probation
  (otherwise each replacement would hand out a fresh set of like tags at once).
- It has new pseudonyms. Accounts must be bound again; the old badges run out with their leases.
- At most one replacement per 30 days per person.

Who can do what:

| Attacker has | Can they take over? | Can they lock the owner out? |
|---|---|---|
| the phone (secret + guardian key), not the eID | uses the secret until the owner replaces it; cannot replace it | no: cannot refuse the owner's replacement (it takes the eID). The owner waits 90 days, or restores a backup and replaces at once |
| the eID, not the phone | only if the owner ignores the app's warning for 90 days; then gets a secret in probation | the owner refuses each request with a re-check |
| the paper code, not the eID | restores and uses the secret alongside the owner | no: the owner replaces at once (guardian key) |
| the eID and the phone, or the eID and the paper code | yes | yes, until the eID is blocked at the bank. That is two of the person's factors |

## 4. Limits

- **Stolen phone, no backup: the thief keeps using the secret during the 90 days.** An immediate freeze
  on eID login alone would let an eID thief switch off anybody's badge at will. Revoking at once takes
  the guardian key (`pop holder revoke`), which is in the backup.
- **A replaced secret can like the same posts again after its probation.** Like tags come from the
  secret, so one person can count twice on an old post, once per replacement, nine or more months
  apart.
- **Whoever holds both the eID and the current secret wins every dispute.** The design sends such cases
  to a desk with an in-person check; the prototype has no desk.
- **If the answer to a replacement is lost on the way** (network failure after the issuer acted), the
  old secret is revoked and the new one never arrived. The person asks again after 30 days. A real
  service would make the request repeatable for a day.
- **The re-check needs a credential that can still renew.** Too late means replacement and probation.
- **The backup host can link a backup to an enrolment record** through the ticket (§2).
- **Unauthenticated endpoints scan the record table** (`/v1/replace/claim`, `/v1/replace/pending`, as
  `/v1/revoke` did before). Rate-limit them at the proxy, and give a real store an index by handle and
  by claim hash.
- **One issuer process.** Changes to a record are serialised by a lock inside the process; several
  issuer processes over one database need compare-and-swap there.
- **`pop holder backup` prints the code to the terminal.** A phone app would show it once on screen.
