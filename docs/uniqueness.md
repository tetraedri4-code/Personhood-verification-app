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

**When can an old key be retired?** When `pop uniqueness records` shows no records under it. People only
log in when they enrol a new device, so records of people who never come back stay under the old key.
In the full design the two-year identity re-check brings everyone back; this prototype has no re-check
yet, so in practice old keys stay. Rotating a key is for a suspected leak, not routine. For routine
hygiene of a shared key use a **refresh** (below), which changes every share and no d.

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

Each operator is its own server with its own share file and three tokens:

```json
{
  "index": 1,
  "eval_token": "…the issuer's token for this operator…",
  "admin_token": "…this operator's administrator…",
  "peer_token": "…shared by the operators…",
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

The administrator's side takes a **cluster file**, a JSON list of `{ "index", "url", "admin_token" }`:

```sh
pop uniqueness dkg      --cluster ops.json --threshold 2          # new key; prints the group key Y
pop uniqueness status   --cluster ops.json                        # epochs, thresholds, evaluation counts
pop uniqueness refresh  --cluster ops.json --key <Y>              # new shares, old ones erased
pop uniqueness reshare  --key <Y> --from ops.json --to new-ops.json --threshold 2
pop uniqueness finalize --key <Y> --epoch <n> --cluster new-ops.json --leavers old-ops.json
```

`reshare` erases the old shares at the operators named in `--from` and `--to` once the new epoch is
verified. If you dealt with fewer than all holders, name the rest under `finalize --leavers`.
`--keep-old` skips the erasing.

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

A round is run by the administrators and is all-or-nothing.

1. `start`: every participant gets the same description of the round. Each checks it against its own
   records. A newcomer, which has no records, checks that the dealers' public verification keys combine
   to Y.
2. `deal`: every dealer picks a random polynomial, sends each receiver its value at the receiver's
   index, and publishes commitments to the coefficients (Feldman). In a reshare the constant term is
   the dealer's current share, and its commitment must equal the dealer's published verification key.
   In key generation the constant term is random.
3. Each receiver checks its value against the commitments.
4. `status`: the administrators compare what every receiver saw. A dealer who sent different
   commitments to different receivers, or anyone who dealt in a dealer's name, shows up here and the
   round is aborted.
5. `commit`: each receiver adds up its values into a new share, computes everyone's new verification
   key, checks that Y did not change, and writes the share to disk. The old share is still there.
6. The administrator checks from public data that the new epoch is complete and combines to Y.
7. `finalize`: older shares are erased. This is the only step that cannot be undone, and an operator
   refuses it for an epoch it does not hold unless told it is leaving.

If a commit fails part-way, the receivers that committed discard the new epoch and everything is as
before. Between commit and finalize operators answer under both epochs, so evaluations never stop.

### Tests

`cargo test -p pop-uniqueness` runs real operators on loopback ports: d unchanged through refresh,
operator replacement and a new threshold; fewer than t operators fail; an unreachable or lying operator
is tolerated; a forged deal aborts the round; a failed commit is undone; shares survive a restart; every
endpoint refuses the wrong token. `cargo test -p pop-cli --test uniqueness` covers the issuer: refusal
to start, rotation with migration, and the threshold service behind a full enrolment.

## 4. Limits of this prototype

- **One coordinator holds every admin token** in the `pop uniqueness` commands. Operators that distrust
  each other should each run the steps against their own operator and compare the transcripts of step 4
  themselves. The operator API allows it; the command line does not do it yet.
- **Key generation is the simple Feldman scheme.** A dealer can bias the key (not learn it), and there
  is no complaint phase: a misbehaving dealer can only make rounds fail. A production service would use
  a DKG with complaints and proofs of possession.
- **Sub-shares travel under TLS only.** Whoever terminates TLS for an operator sees its sub-shares, which
  is that operator's own share and no more.
- **The peer token is shared.** An operator can deal in another's name; the transcript comparison
  catches it, at the cost of a failed round.
- **The rate limit is the only brake on guessing.** Identity codes are guessable. Whoever holds the
  issuer's evaluation tokens can test guesses against the enrolment table at `max_evals_per_minute`.
  Set the limit close to the real enrolment rate and watch the evaluation counts in `status`.
- **The issuer still sees the identity code** for the moment of the login, as before. The threshold
  service takes the *key* away from the issuer, not the login.
- **t colluding operators can recompute K.** That is what the threshold means.
- **Shares sit in a plain file** (mode 0600) and are not wiped from memory. Use a hardware module for
  more.
- **`/v1/public` is open** and shows verification keys, epochs and evaluation counts.
