# Data usage of the app

Measured on 19 November 2026 (first on 16 November, before the change to syncing) with
`cargo test --release -p pop-cli --test data_usage -- --ignored --nocapture`, which runs one person through every operation and counts the JSON bodies the holder app
sends and receives. Default settings: LegoGroth16, revocation tree of depth 8.

Bodies only. Each operation is two or three HTTPS requests; add about 0.5 kB of headers per request,
and about 5 kB once per connection for the TLS handshake.

## Per operation (holder app)

| Operation | How often | Sent | Received |
|---|---|---|---|
| Proving keys | once per device, cached | 0 | **4.7 MB** |
| Enrol | once | 0.6 kB | 1.7 kB |
| Bind an account | per account; again every nine months | 4.2 kB | 0.3 kB |
| Report a like | per like | 2.8 kB | 0.2 kB |
| Renew | every quarter | 2.7 kB | 0.3 kB |
| Update the backup | with each renewal | 5.7 kB | 0 |
| Identity re-check (with backup update) | every two years | 8.4 kB | 0.7 kB |
| Look for a waiting replacement | at app start | 0 | 14 B + 120 B per waiting request in the system |
| Replace the secret (with backup update) | rarely | 6.4 kB | 0.9 kB |
| Restore a backup | rarely | 0 | 5.6 kB |

With Bulletproofs instead of LegoGroth16 there are no proving keys to download, and each proof is about
3.6 kB larger: bind 8.5 kB, like 6.5 kB, renew 6.2 kB, re-check 6.3 kB sent.

What changed on 19 November 2026 (before, a like received 1.0 kB):

- The issuer's parameters (0.8 kB) are reused for ten minutes instead of fetched before every proof.
  The first proof after a pause still fetches them.
- The revocation list is kept on the device. Each proof asks only for handles revoked since the last
  time, plus up to 63 already known (the holder asks from a multiple of 64, see
  [security.md](security.md) #28–31): about 0.1 kB, plus about 20 bytes per new revocation, gzipped.
  A new device downloads the whole list once.

The upload side is the proof itself and cannot shrink without another proof system.

## One person, one year

A person with two bound accounts who reports ten likes a day:

| | Bodies | With headers and handshakes (rough) |
|---|---|---|
| First day: keys, enrolment, two bindings, backup | 4.8 MB | 4.8 MB |
| Renewals and backup updates (4) | 35 kB | 70 kB |
| Bindings renewed (2 to 3) | 12 kB | 25 kB |
| Likes (3,650) | 11 MB | 15 to 20 MB |
| Re-check (half of one) | 5 kB | 10 kB |
| **A year after the first day** | **about 11 MB** | **about 15 to 20 MB** |

Almost all of it is the uploaded like proofs: about 3 kB each in bodies, 4 to 5 kB on the wire. A person
who reports no likes uses under 150 kB a year after the first day. The rough column is an estimate of
HTTP and TLS overhead, not a measurement.

## The browser extension

The extension shows badges and counts for every account and post on a page, without telling the
directory which ones the person looks at. It therefore keeps the platform's whole list of bound
accounts and the whole table of like counts, in the browser's storage, and once a minute while a page
of that platform is open asks only for what changed since the last time.

| | Size |
|---|---|
| A bound account in the list | about 260 B, about 50 B gzipped (measured on 1,000 random Bluesky-like entries) |
| A post in the counts table | Bluesky (post ids are AT URIs): about 78 B, 29 B gzipped. Mock feed: 13 B |
| A sync with no changes | about 140 B for list and table together |
| A sync with changes | 140 B plus each changed account or post once, however often it changed |

So the first sync costs the whole list once: for 10,000 bound accounts and 100,000 posts with likes on
Bluesky, about 0.5 MB + 2.9 MB gzipped. After that the traffic is the platform's changes while the
person browses, and, at the first sync of a session, the changes since the last one. Before this change
the extension downloaded both lists in full every minute (23 MB per hour of browsing at 1,000 accounts
and 10,000 posts); now that example costs a few kB per hour.

**What still grows with the system.** The changes are those of the whole platform. If 100,000 enrolled
people each report ten likes a day, roughly a million counts change a day; a person browsing all day
would download each post whose count changed once per minute it changed in: up to about 30 MB a day
at that size if every like is on a different post, less in practice. Someone who browses an hour a day
pays about the same at the start of the session, for the posts changed since the last one. The table also never forgets old posts. The next steps, not built, are in the design and in
[real-servers.md](real-servers.md) §5: split the table into buckets by a prefix of the hashed post id and
keep only buckets for posts actually seen, sync less often in the background, and drop posts older than
a few weeks from the synced table (asking for one old post's bucket when it is shown).

Removed claims are remembered for 30 days; a reader away longer downloads the whole list again.

The extension itself is 28 kB.
