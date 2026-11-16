# Uniqueness keys

The issuer never stores an identity code. It stores a **deduplication key** d = F_K(country, identity
code), where K is a secret key. Two logins of one person give the same d; without K nobody can test
whether a given person is enrolled.

Everything about one-person-one-enrolment therefore rests on K:

- If K **leaks**, enrolment records can be tested against known identity codes.
- If K is **lost or silently replaced**, every d changes, nobody is recognised any more, and every
  enrolled person can enrol a second time.

This page covers how the prototype guards K: key versions, the refusal to start without a key, key
rotation, and the threshold service that keeps K in shares held by several operators.

The issuer reaches all of this through one interface, `UniquenessService`
(`crates/pop-protocol/src/uniqueness.rs`):

```rust
async fn versions(&self) -> Result<Vec<String>>;                       // newest first
async fn dedup_keys(&self, country: u32, subject: &str) -> Result<Vec<DedupKey>>;  // d under every version
```

Two implementations ship. Choose one in the issuer configuration:

| `uniqueness.kind` | Who holds K | Crate |
|---|---|---|
| `hmac` (default) | the issuer, in a key file | `pop-issuer` (`HmacUniqueness`) |
| `threshold` | t-of-n separate operators, as shares | `pop-uniqueness` |

## 1. Key versions and the refusal to start

Every enrolment record carries the version of the key its d was made under (`key_version`). A version
is a fingerprint of the key (`hmac:…`, `threshold:…`), not a counter, so a key file that was regenerated
or swapped is noticed.

When the issuer starts it compares the versions in its records with the versions the uniqueness service
holds. **If any record sits under a version that is missing, the issuer refuses to start** and says which
version and how many records. In the single-operator case it also refuses to start when records exist
and no key is found at all, instead of making a fresh key.

Refusing is deliberate. An issuer that started anyway would work, look healthy and enrol everyone
twice.

To recover: restore the missing key from backup. If the key is gone for good, the records under it can
never be matched again; removing them from the `enrolments` table is an explicit decision that those
people may enrol again.

At login, a uniqueness service that cannot answer for **every** live version makes the issuer answer
"try again later" (HTTP 503). It never treats a missing answer as "not enrolled".

Records made before key versions existed (the first prototype) have no `key_version` and also stop the
issuer. Start from an empty data directory.

## 2. Rotating a key

A new key means new d values, so rotation needs migration:

1. The service holds the old and the new key. `dedup_keys` returns d under both.
2. At each login the issuer looks the person up under every version, newest first.
3. A match under an old version means "already enrolled", and the record is rewritten under the newest
   version on the spot.
4. A person not found under any version enrols under the newest.

So nobody gets a second enrolment during or after a rotation, and old keys empty out as people log in.

**Single operator:**

```sh
pop uniqueness rotate-key --config issuer.json    # writes data_dir/uniqueness-keys/NNNN.key
# restart the issuer
pop uniqueness records --config issuer.json       # records per key version
```

Key files are `data_dir/uniqueness-keys/0001.key`, `0002.key`, …; the highest number is current. Keep
the older files. The issuer will not start without them while records remain under them.

**Threshold service:** generate a new key with `pop uniqueness dkg`, append its group key to
`uniqueness.keys` in the issuer configuration (last entry = current), restart the issuer. The operators
keep their shares of the old key.

**When can an old key be retired?** When `pop uniqueness records` shows no records under it. A record moves
when its owner logs in.
The two-year identity re-check ([recovery.md](recovery.md) §1) brings every active person back within
two years, and their record moves then. Records of people who never return stay under the old key, so
keep it; `pop uniqueness records` shows how many are left. Rotating a key is for a suspected leak, not
routine. For routine hygiene of a shared key use a **refresh** (below), which changes every share and
no d.

## 3. The threshold service

### What it computes

K is never in one place. n operators each hold a share k_i; any t of them can evaluate, fewer learn
nothing.

- The function is d = SHA-256("pop-dedup-v2", Y, x, H1(x)^K), with x = `country|identity code`, H1 a
  hash to the curve group G1 of BLS12-381 and Y = g2^K the public **group key** (the "2HashDH"
  construction of Jarecki, Kiayias, Krawczyk and Xu, 2017).
- The issuer **blinds** the request: it sends a = H1(x)^r for a fresh random r. The operators see a
  random point and never learn whom they are asked about.
- Operator i answers a^{k_i}. The issuer combines t answers with Lagrange coefficients, removes r, and
  **checks the result against Y** with a pairing: e(u, g2) = e(H1(x), Y). A wrong, stale or missing
  share gives an error, never a wrong d. If one operator lies, the issuer tries other subsets.
- Shares are Shamir shares over the scalar field of the curve (a prime of about 2^255). All arithmetic
  is modulo that prime, so nothing overflows however often shares are refreshed.

Y is pinned in the issuer configuration. Operators cannot swap the key under the issuer.

### Why refresh and operator changes do not change d

Both give out new shares **of the same K**. Y stays, H1(x)^K stays, d stays. Only a new key (a new Y, a
new version, §2) changes d.

- **Refresh**: every operator gets a new share and erases the old one. A share stolen before the
  refresh is useless together with shares from after it. An attacker must hold t shares of the same
  epoch.
- **Reshare**: the current holders deal new shares to another set: add, remove or replace operators, or
  change the threshold. Operators that leave erase their share.
- **A lost share** is repaired the same way: t remaining holders reshare to the full set.

If fewer than t shares of an epoch survive, K is gone. That is the lost-key case of §1: the issuer
answers 503 for everyone and enrols nobody twice.

### Running it

Each operator is its own server with its own state file and two tokens:

```json
{
  "index": 1,
  "eval_token": "…the issuer's token for this operator…",
  "admin_token": "…this operator's administrator…",
  "state_file": "/var/lib/pop/uniqueness/shares.json",
  "max_evals_per_minute": 120,
  "min_threshold": 2
}
```

```sh
pop uniqueness operator --config operator1.json --listen 127.0.0.1:4101
```

`index` is the operator's number in the sharing (1, 2, 3, …); it never changes and is never reused.
Put each operator behind a TLS reverse proxy. The clients refuse plain http except on loopback.

At its first start an operator makes an **identity key** and keeps it in the state file next to its
shares. `GET /v1/public` shows the public half. Operators have no shared secret: a message between
operators counts only if it is signed with the identity key that the round names for its sender, and
a sub-share is encrypted to the identity key of the operator it is for. Give the other administrators
your operator's identity key over a channel you trust (it is 192 hex characters), and pin theirs.

**Operators with different administrators.** Nobody needs anyone else's admin token.

```sh
# one administrator writes the round and sends the file to the others
pop uniqueness round new-dkg     --members members.json --threshold 2 --out round.json
pop uniqueness round new-reshare --key <Y> --from members.json --to new-members.json --threshold 2 --out round.json

# every administrator reads it, then joins with their own operator
pop uniqueness round show --spec round.json
pop uniqueness round join --spec round.json --operator my-operator.json
```

`members.json` is a list of `{ "index", "url", "identity" }`. With `identity` left out, the key the
operator publishes at that address is taken on trust. `my-operator.json` is `{ "index", "url",
"admin_token" }` of your own operator. `join` approves the round at your operator and keeps it moving;
it returns when the round is done at your operator, has failed (and says who is at fault, if the
evidence names someone), or the timeout passes. `new-reshare` with the same members in `--from` and
`--to` is a refresh.

**One party runs every operator** (the demo, tests, a first deployment). A **cluster file** is a list
of `{ "index", "url", "admin_token" }`:

```sh
pop uniqueness dkg      --cluster ops.json --threshold 2          # new key; prints the group key Y
pop uniqueness status   --cluster ops.json                        # epochs, thresholds, evaluation counts
pop uniqueness refresh  --cluster ops.json --key <Y>              # new shares, old ones erased
pop uniqueness reshare  --key <Y> --from ops.json --to new-ops.json --threshold 2
```

These run the same round as `round join`, for all operators at once.

Issuer configuration:

```json
"uniqueness": {
  "kind": "threshold",
  "operators": [
    { "index": 1, "url": "https://uniq1.example.org", "token": "…eval token of operator 1…" },
    { "index": 2, "url": "https://uniq2.example.net", "token": "…" },
    { "index": 3, "url": "https://uniq3.example.com", "token": "…" }
  ],
  "keys": ["<group key Y, hex>"]
}
```

List every operator that holds or will hold a share. One that holds none yet answers "no share" and is
ignored. After an operator change, update the list at the next restart; nothing else changes.

`pop demo` runs all of this locally: three operators 2-of-3 plus a standby, a refresh, a replaced
operator, and a second enrolment refused afterwards. `pop demo --uniqueness hmac` uses the keyed hash.

### How a round works

A round is described by a **spec**: kind (key generation or reshare), dealers, receivers, their
addresses and identity keys, the new threshold, and for a reshare the group key, the epoch dealt from
and the dealers' verification keys. The round's id is a hash of the spec, and every message is signed
over that id. An operator takes part only in a round its own administrator approved, and checks the
spec against its own records first. A newcomer, which has no records, checks that the dealers'
verification keys combine to Y.

1. **Commit.** Every dealer picks a random polynomial and sends everyone a hash of its Feldman
   commitments. Nobody shows anything else until it holds every dealer's hash, so no dealer can choose
   its contribution after seeing the others'.
2. **Deal.** Every dealer sends each receiver the commitments and the polynomial's value at the
   receiver's index, encrypted to the receiver, with a proof that the dealer made the ciphertext
   itself. The receiver checks the hash, the value against the commitments, and
   - key generation: a proof that the dealer knows its contribution (no "rogue key");
   - reshare: that the constant term's commitment is the dealer's published verification key, so the
     dealer shares its real share.
3. **Complaint.** A receiver that gets a bad deal publishes the dealer's signed commit and deal, and
   opens the ciphertext with a proof that it used its own key. Every operator checks the evidence for
   itself. Either the dealer is convicted, or the complaint does not hold and the complainer is. A
   ciphertext that is malformed convicts its dealer as it stands, and the receiver opens nothing.
4. **Ready.** A receiver whose deals all check out says so, with a hash over every dealer's commit and
   the signed commits themselves. If two operators hold different commits from one dealer, both now
   have the two signatures and name that dealer. A ready message whose hash its own evidence does
   not explain convicts its sender.
5. **Store.** When every receiver is ready with the same hash, each adds up its values into a new
   share, computes everyone's new verification key, checks that Y did not change, writes the share to
   disk and says so.
6. **Erase.** When every receiver has confirmed that its new share is on disk, each operator erases
   its older shares of the key by itself. An operator that left erases its last one.

A round that fails or stalls before step 5 changes nothing. One that stalls after step 5 leaves the
new epoch at some operators: nothing was erased, the old epoch still works everywhere, operators
answer under both, and the next successful round supersedes the leftover. A failure that names an
operator says `operator N is at fault; run the round again without it`.

After an operator **restarts in the middle of a round**, start a new round. A round lives in memory;
an operator that came back would commit to a new polynomial under the old round's id and be named as
having signed two commits.

### Tests

`cargo test -p pop-uniqueness` runs real operators on loopback ports: d unchanged through refresh,
operator replacement and a new threshold; fewer than t operators fail; an unreachable or lying operator
is tolerated; messages need the sender's signature; a round runs with each administrator driving only
their own operator; a dealer that sends a wrong value, a receiver that complains falsely, a dealer
that shows two receivers different polynomials, a receiver that lies about what it saw and a dealer
that copies a ciphertext are each named; a stalled round loses nothing; shares survive a restart; every
endpoint refuses the wrong token. `cargo test -p pop-cli --test uniqueness` covers the issuer: refusal
to start, rotation with migration, and the threshold service behind a full enrolment.

## 4. Limits of this prototype

- **A dealer can stop a key generation after seeing the result.** Commitments are fixed before anyone
  deals, so a dealer cannot steer the key; but it can refuse to finish a round whose key it does not
  like, and try again. It is named each time. For this key that gains nothing (any random key is as
  good as another).
- **Blame is evidence for the administrators, not an automatic exclusion.** The round fails and says
  who; the administrators run it again without that operator.
- **Identity keys are pinned by the administrators.** If `identity` is left out of the members file,
  the key published at the operator's address is trusted. Within a key's lifetime an operator refuses
  a spec that names another identity key for an operator it already knows.
- **The identity key sits in the state file** with the shares (mode 0600), and neither is wiped from
  memory. Use a hardware module for more.
- **The rate limit is the only brake on guessing.** Identity codes are guessable. Whoever holds the
  issuer's evaluation tokens can test guesses against the enrolment table at `max_evals_per_minute`.
  Set the limit close to the real enrolment rate and watch the evaluation counts in `status`.
- **The issuer still sees the identity code** for the moment of the login, as before. The threshold
  service takes the *key* away from the issuer, not the login.
- **t colluding operators can recompute K.** That is what the threshold means.
- **`/v1/public` is open** and shows verification keys, epochs and evaluation counts.
- **Migration to a new key happens when a person logs in** (enrolment attempt, re-check or
  replacement). With the two-year re-check every active record moves within two years; records of
  people who never come back stay under the old key, which must be kept for them.
