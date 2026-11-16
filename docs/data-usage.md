# Data usage of the app

Measured on 16 November 2026 with `cargo test --release -p pop-cli --test data_usage -- --ignored
--nocapture`, which runs one person through every operation and counts the JSON bodies the holder app
sends and receives. Default settings: LegoGroth16, revocation tree of depth 8.

Bodies only. Each operation is two or three HTTPS requests; add about 0.5 kB of headers per request,
and about 5 kB once per connection for the TLS handshake.

## Per operation (holder app)

| Operation | How often | Sent | Received |
|---|---|---|---|
| Proving keys | once per device, cached | 0 | **4.7 MB** |
| Enrol | once | 0.6 kB | 2.5 kB |
| Bind an account | per account; again every nine months | 4.2 kB | 1.1 kB |
| Report a like | per like | 2.8 kB | 1.0 kB |
| Renew | every quarter | 2.7 kB | 1.1 kB |
| Update the backup | with each renewal | 5.7 kB | 0 |
| Identity re-check (with backup update) | every two years | 8.4 kB | 2.3 kB |
| Look for a waiting replacement | at app start | 0 | 14 B + 120 B per waiting request in the system |
| Replace the secret (with backup update) | rarely | 6.4 kB | 2.6 kB |
| Restore a backup | rarely | 0 | 5.6 kB |

With Bulletproofs instead of LegoGroth16 there are no proving keys to download, and each proof is about
3.6 kB larger: bind 8.5 kB, like 6.5 kB, renew 6.2 kB, re-check 6.3 kB sent.

Of the 1.0 kB received per proof, 0.8 kB is the issuer's parameters, fetched again each time. Caching
them for a day would cut the download side of a like to about 0.1 kB.

## One person, one year

A person with two bound accounts who reports ten likes a day:

| | Bodies | With headers and handshakes (rough) |
|---|---|---|
| First day: keys, enrolment, two bindings, backup | 4.8 MB | 4.8 MB |
| Renewals and backup updates (4) | 38 kB | 70 kB |
| Bindings renewed (2 to 3) | 13 kB | 25 kB |
| Likes (3,650) | 13.9 MB | 20 to 25 MB |
| Re-check (half of one) | 5 kB | 10 kB |
| **A year after the first day** | **about 14 MB** | **about 20 to 25 MB** |

Almost all of it is likes: about 4 kB each in bodies, 6 to 7 kB on the wire. A person who reports no
likes uses under 150 kB a year after the first day.

## What grows with the number of users

Two downloads are whole lists in the prototype, and they grow with the system, not with the person:

- **The revocation list** comes with every proof (bind, like, renew, re-check): 119 B plus about 20 B
  per revoked credential. At 1,000 revocations that is 20 kB per like; at the tree's capacity of 65,000
  it would be 1.3 MB per like. The design's bucketed lookup ([real-servers.md](real-servers.md) §4)
  makes this a few kB whatever the size.
- **The browser extension** downloads the full list of bound accounts of a platform (about 240 B each)
  and the full table of like counts (about 15 B per post) once a minute while a page of that platform
  is open. At 1,000 bound accounts and 10,000 posts that is 0.4 MB a minute, about 23 MB per hour of
  browsing. At 100,000 accounts it is 24 MB a minute. Whole lists are downloaded so that the directory
  does not learn which accounts and posts a person looks at; a real service would serve them in
  buckets by hash prefix, or as daily snapshots with small updates, and compressed.

The extension itself is 25 kB.
