# Relays (Oblivious HTTP)

Without a relay, the directory sees the internet address and the time of every binding, like report and
download, and the issuer sees them for every renewal. The proofs reveal nothing, but the address can
link reports to each other and to a person. A relay removes the address.

The prototype uses Oblivious HTTP (RFC 9458):

```
holder app / extension ──encrypted request──▶ relay ──same bytes──▶ gateway ─▶ issuer or directory
                       ◀──encrypted answer─── (sees the address,  (sees the request, only the
                                               not the request)    relay's address)
```

The client encrypts each request to the server's gateway key (HPKE, RFC 9180: X25519, HKDF-SHA256,
AES-128-GCM) as binary HTTP (RFC 9292). The relay passes the bytes on and the answer back. Unless the
relay's operator and the server's operator work together, neither can tie a request to an address. The
relay must therefore be run by someone other than the operator of the issuer and the directory.

## What is built

| Part | Where | What it does |
|---|---|---|
| Gateway | `pop-ohttp::gateway`, mounted by `pop issuer`, `pop directory` and the devnet | `POST /ohttp` decrypts a request, hands it to the server's own routes and encrypts the answer; `GET /ohttp/keys` serves the key. The server's code is unchanged. Only `content-type` and `accept` are passed on from the inner request; the server sees no address at all. |
| Relay | `pop-ohttp::relay`, `pop relay` | `POST /<name>` forwards to the named gateway, with the body and nothing else (no address, no headers), and keeps no log. `GET /<name>/keys` serves the gateway's key, fetched once for everyone. |
| Rust client | `pop-ohttp::Oblivious`, a `pop_protocol::http::Transport` | Used by the holder app for every request to the issuer or directory when a relay is set. |
| Extension client | `extension/src/ohttp.js` | The same with WebCrypto, no library. Used for every directory request when "Relay address" is set in the options. |

The demo and the end-to-end tests send all holder and extension traffic through the devnet's relay
(`http://127.0.0.1:4004/issuer`, `/directory`).

## Using it

```sh
# someone other than the server operator runs the relay
pop relay --listen 127.0.0.1:4004 \
          --gateway issuer=https://issuer.example.org --gateway directory=https://directory.example.org

# the holder app
pop holder --issuer-relay https://relay.example/issuer --directory-relay https://relay.example/directory ...
# or POP_ISSUER_RELAY / POP_DIRECTORY_RELAY
```

In the extension: options, "Relay address", `https://relay.example/directory`. The relay's host must be
in the extension's `host_permissions`, as the directory's is.

A hosted relay that speaks RFC 9458 can replace `pop relay`: point it at
`https://directory.example.org/ohttp` and give clients its address. The clients fetch the key from
`<relay address>/keys`, which such a relay may not serve; the client would then need the key from
elsewhere (a small change in `Oblivious::keys` and `ohttp.js`).

## The key

The gateway makes a new key at each start (`Gateway::rotate` replaces it while running). A request
encrypted to an old key is refused before it reaches the server, and the client fetches the key again
and resends it once.

Clients fetch the key through the relay, never from the server directly, and the relay keeps one copy
for everyone for an hour (and at least ten minutes even if the gateway says its key changed). This is
so that a server cannot hand one client a key of its own and recognise that client's requests by it.
It still could give a different key in each ten-minute window, and so tell apart clients that fetched in
different windows. With many users that says little; a real deployment should publish its key where
everyone can check it is the same (for instance in the issuer's signed parameters) and have clients
compare.

## Size and time

Encryption hides what a message says, not how long it is or when it is sent. Both are issuer settings
(`policy` in the issuer configuration, public at `GET /v1/policy` and in `/v1/params`):

- **`pad_sizes`** (default 1, 4, 16, 64, 256 KiB and 1 MiB). Every request and answer through a relay
  is padded with zero bytes (RFC 9292 allows this) to the smallest size in the list that fits, or
  beyond the largest to a multiple of it. Without it the relay could tell a like report from a
  download, or match an answer to one of the public count buckets by its length. Both gateways pad
  answers with the issuer's sizes and name them inside every encrypted answer; clients pad requests
  with the sizes of the last answer (the defaults until then).
- **`like_window_secs`** (default 1800, half an hour). Likes go out on a schedule that is the same for
  everyone: windows of this length counted from 1 January 1970 (UTC), so every half-hour mark is a
  window boundary. A like clicked in one window is proved and sent at a random moment of the next. The
  relay sees when a person's computer sends something, and anyone can see when a public count goes up;
  without the schedule, the two together would tie the person to the post when there are few users.
  With it, both show only the window of the click: every like clicked in that window by anyone looks the
  same. The sends are spread over the whole next window, so the servers see no spike at the marks. A
  like waits between a moment and two windows (one hour at the default). The extension shows the like at once and keeps showing it until it has surely
  arrived; the holder keeps waiting likes in the wallet across a restart. The proof is made after the
  wait, so it uses the revocation root of that moment. If the app is closed when its like is due, the like
  stays queued and goes out in the window after the app starts again: later, which tells no more. (`pop devnet` and `pop demo` default to 20 s;
  `--like-window-secs` changes it.)

## What it does not do

- **No mixing and no cover traffic.** The design's relays also mix reports and add dummy ones (§4.7).
  The schedule hides a like among those clicked in the same half-hour; with very few users that window
  may still hold only one person's likes. The window marks follow the device's clock: a device whose
  clock is far off sends outside the others' windows and stands out. Bindings and renewals are sent at once: a binding right after an enrolment is
  still linkable by timing when there are few users.
- **Size classes are coarse.** Messages in the same class look the same; a like report (about 4 KiB)
  is still in a different class from a small download.
- **The eID login goes straight to the identity provider and back to the issuer** in the browser. The
  issuer learns who the person is at that moment anyway.
- **Answers are capped at 32 MB.** The full list of bound accounts passes through the relay; at a very
  large scale it would not. Counts switch to buckets as the platform grows.
- **The relay can still count** how many requests an address sends and when, and drop them.
