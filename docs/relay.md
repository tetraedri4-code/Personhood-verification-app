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

## What it does not do

- **No delay and no cover traffic.** The design's relays hold reports back and mix them (§4.7). Here a
  request goes through at once, so the server still sees when a report was made, and a binding sent
  right after an enrolment is still linkable by timing when there are few users.
- **The eID login goes straight to the identity provider and back to the issuer** in the browser. The
  issuer learns who the person is at that moment anyway.
- **Answers are capped at 32 MB.** The full list and counts table pass through the relay; at a very
  large scale they would not, which the bucketed downloads address.
- **The relay can still count** how many requests an address sends and when, and drop them.
