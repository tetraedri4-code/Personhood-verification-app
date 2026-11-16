# Running real servers

The mock setup (`pop devnet`) runs four services in one process with in-memory storage. This page says
what to change for a deployment other people can reach. Two of the four are yours to run (issuer,
directory); the other two are replaced (mock identity provider → a real one, mock feed → real platforms).

## 1. Run the services separately

They already talk to each other only over HTTP, so this is configuration:

```sh
pop issuer    --config /etc/pop/issuer.json --listen 127.0.0.1:4002
pop directory --issuer-url https://issuer.example.org --data-dir /var/lib/pop/directory \
              --listen 127.0.0.1:4003 --bluesky
```

Put both behind a TLS reverse proxy (Caddy, nginx). The services speak plain HTTP and listen on
loopback by default; nothing should reach them except the proxy. At the proxy:

- **TLS** with a public certificate. The holder app and the extension refuse plain http except on
  loopback.
- **Rate limits** per address on `POST /v1/enrol/start`, `/v1/bindings`, `/v1/likes` and `/v1/renew`.
  The services themselves only cap open enrolment sessions; verifying a proof costs the server about
  10 ms (LegoGroth16) or 300 ms (Bulletproofs), which is cheap to abuse.
- **No access logs with addresses** on the directory's read endpoints and on `/v1/likes`, or short
  retention. The design goes to some length so the operator cannot tell who likes what; an access log
  with IP addresses and timestamps undoes part of that.
- **Body size limit** of 1 MB is plenty.

The issuer and the directory can be on different hosts and under different organisations. The directory
needs nothing secret: it reads the issuer's public keys from `/v1/params`.

Holders and extensions then use:

```sh
pop holder --issuer-url https://issuer.example.org --directory-url https://directory.example.org ...
```

and the same directory address in the extension's options.

## 2. Storage

Both services keep all state through one trait (`crates/pop-storage/src/lib.rs`):

```rust
#[async_trait]
pub trait Store: Send + Sync {
    async fn get(&self, table: &str, key: &str) -> Result<Option<Value>>;
    async fn put(&self, table: &str, key: &str, value: Value) -> Result<()>;
    async fn insert_new(&self, table: &str, key: &str, value: Value) -> Result<bool>;
    async fn delete(&self, table: &str, key: &str) -> Result<()>;
    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>>;
    async fn count(&self, table: &str) -> Result<u64>;
}
```

`JsonFileStore` (used when `data_dir` is set) rewrites one JSON file per table on every change. That is
fine for a pilot of a few thousand people on one machine and wrong beyond it.

To use a database:

1. Create a crate `pop-storage-postgres` (or similar) depending on `pop-storage`.
2. Implement `Store`. One table `(tbl text, key text, value jsonb, primary key (tbl, key))` is enough.
3. **`insert_new` must be atomic** (`INSERT ... ON CONFLICT DO NOTHING` and report whether a row was
   inserted). One enrolment per person, one use per proof and one count per like tag all rest on it.
4. Build it in `wiring::store` in `crates/pop-cli/src/wiring.rs`.

Tables in use:

| Service | Table | Key | Holds |
|---|---|---|---|
| issuer | `enrolments` | deduplication key d | handle, guardian public key, status, day, uniqueness key version |
| issuer | `enrol_sessions`, `enrol_states` | random ids | sessions in progress, deleted at the end or after 15 minutes |
| issuer | `revoked` | handle | day of revocation |
| directory | `bindings` | platform, account, pseudonym | the claim and its proof |
| directory | `nyms` | platform, pseudonym | account the pseudonym is bound to |
| directory | `likes` | platform, post, tag | day |
| directory | `like_counts` | platform, post | count |
| directory | `nonces` | kind, platform, nonce | day, pruned after three days |

Two places scan a whole table and need an index or a query once there are many rows: the issuer's
`revoke` (find the enrolment by handle) and the directory's `list` and `table`. With a database, add
methods for those instead of calling `list`.

The directory runs as one process: it serialises writes with an in-process lock. To run several, move
the "one account per pseudonym" and "count once" logic into database transactions.

## 3. Keys

With `data_dir` set, the issuer writes to `data_dir/keys/` (and the uniqueness keys to
`data_dir/uniqueness-keys/`):

| File | What | If it leaks |
|---|---|---|
| `issuer.key` | BBS signing key | credentials can be forged |
| `witness.key` | signs revocation handles | with the issuer key: forged credentials pass |
| `uniqueness-keys/NNNN.key` | keys the deduplication hash (single-operator mode) | enrolment records can be tested against known identity codes |
| `lego2-*.bin` | proving keys | public; but see below |

For anything beyond a demo:

- Keep `issuer.key` and `witness.key` under different operators, as the design intends. The witness
  exists so that the issuer alone cannot mint. Today both live in one process; the seam is
  `WitnessKey::sign_handle` in `pop-issuer/src/service.rs`, which becomes a call to a separate service.
- Move the keys into a hardware module or a cloud key service. Both keys are used in a handful of
  places in `pop-crypto/src/scheme.rs` (`issue_blind`, `reissue`, `sign_handle`).
- Run the uniqueness key as a threshold service (`"uniqueness": {"kind": "threshold", ...}`), as in
  design v2 §4.2: several operators each hold a share, and no single one can test whether a given
  person is enrolled. Setup, refresh, operator changes and key rotation are in
  [uniqueness.md](uniqueness.md).
- **Run a real setup ceremony for LegoGroth16**, or use Bulletproofs. The issuer currently generates the
  proving keys alone, and whoever ran the setup can forge proofs. See [crypto.md](crypto.md).
- Back up `enrolments` and the uniqueness keys together. Without the key of its records nobody can be
  recognised as already enrolled, so the issuer refuses to start ([uniqueness.md](uniqueness.md) §1).

### Recovery settings

`replace_wait_days` in the issuer configuration (default 90) is how long a replacement of a lost secret
waits when the old guardian key did not sign it ([recovery.md](recovery.md) §3). The two backup routes
can be served from another host than the issuer; they share only the `backup_tickets` table with it
([recovery.md](recovery.md) §2). Changes to an enrolment record (revoke, re-check, replace, claim) are
serialised by a lock inside the issuer process: run one issuer process, or move that into your
database as a compare-and-swap on the record.

The proving-key files are named `lego2-*.bin` since the like statement changed; older `lego-*.bin`
files are unused and can be deleted.

## 4. Revocation list

`GET /v1/revocations` returns every revoked handle, and each holder rebuilds the tree to find its own
path without telling anyone its handle. That stops scaling in the tens of thousands. The design's answer
(§4.6) is a bucketed lookup: the holder asks for the bucket of leaves around its handle plus the path
above. `IssuerApi::revocations` is the one method to change, with `Holder::tree`.

The tree depth is in the scheme configuration: capacity is 4^depth − 1 revoked handles (depth 8: about
65,000; depth 12: about 16 million). Changing it needs new proving keys.

## 5. Like counts

The extension downloads the whole counts table (`GET /v1/likes/table`) so the directory does not learn
which posts a person looks at. At scale, serve it in buckets by a prefix of the hashed post id, so a
request reveals only a bucket. An enrolled person can report likes for post ids that do not exist; the
directory only checks the id's form. Tags are unlinkable by design, so this cannot be limited per
person. Cap it at the proxy and prune posts with a single tag from the table if it becomes a problem.

## 6. Network privacy

The design routes every proof through delaying relays (§4.7). The prototype sends them directly, so the
directory sees the sender's address and the time. Both clients take a `reqwest::Client`
(`HttpClient::with_client`), which is where an Oblivious HTTP relay or a proxy goes.

## 7. Before real people use it

Operator duties from the voluntary-app report §2.2, none of which is code: a data protection impact
assessment, a privacy notice and consent text for enrolment, the public list and like reports, a talk
with the Data Protection Ombudsman, and an independent security audit of this code.
