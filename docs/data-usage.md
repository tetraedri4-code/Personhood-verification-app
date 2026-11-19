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
accounts in the browser's storage, and once a minute while a page of that platform is open asks only
for what changed since the last time. It does the same with the table of like counts while the
platform has few posts with likes, and then switches to buckets (below).

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

**What still grows with the system: count buckets.** Synced whole, the counts table grows with the
platform: if 100,000 enrolled people each report ten likes a day, roughly a million counts change a
day, up to about 30 MB a day for someone browsing all day. So once a platform has more posts with
likes than one bucket holds (the directory's `--bucket-posts`, default 32), the extension stops syncing
the table and asks instead for the buckets of the posts on screen:

- A post's bucket is the top bits of SHA-256(platform | post id). The directory chooses how many bits so
  that a bucket holds about 32 posts with likes on average (`GET /v1/likes/buckets?platform=`), and
  more bits as the platform grows (at most 20, about a million buckets).
- One request per screen (`POST /v1/likes/buckets`, up to 64 buckets), however many posts it shows.
  A bucket fetched in the last minute is not fetched again.
- The directory learns which buckets were asked for, not which of their posts: about 1 in 32.

Cost per screen of new posts: one bucket per post (posts on one screen rarely share a bucket), each
about 32 posts at the sizes above: about 2.5 kB per bucket for Bluesky ids, about 1 kB gzipped. A
screen of 10 new posts is then about 25 kB, 10 kB gzipped (through a relay: not compressed, and padded
to the next size class, here 32 kB). This is an estimate from the per-post sizes above, not a
measurement. It no longer depends on how many likes the whole platform gets, only on how much the
person scrolls. A larger `bucket_posts` hides more and costs proportionally more.

Removed claims are remembered for 30 days; a reader away longer downloads the whole list again.

The extension itself is 28 kB.
