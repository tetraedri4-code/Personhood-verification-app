# Architecture

## Parts and who talks to whom

```
 person's device                      operator                         outside
┌────────────────────┐  IssuerApi   ┌───────────┐ IdentityProvider ┌──────────────────┐
│ holder app         │─────────────▶│ issuer    │─────────────────▶│ ID provider      │
│ (pop-holder)       │              │           │ UniquenessService┌──────────────────┐
│  secret, proofs    │              │           │─────────────────▶│ uniqueness ops   │
│                    │              │           │ Store            │ (t-of-n, or a    │
│                    │              │           │                  │  keyed hash)     │
│                    │              │           │                  └──────────────────┘
│                    │ DirectoryApi ├───────────┤
│                    │─────────────▶│ directory │ IssuerApi (public keys, revocation root)
│                    │              │           │ Platform (read public bio, optional)
│                    │              │           │ Store
│                    │  Platform    └───────────┘                  ┌──────────────────┐
│                    │────────────────────────────────────────────▶│ platform         │
└─────────▲──────────┘ publish the code                            │ (mock feed,      │
          │ local API, pairing token                               │  Bluesky)        │
┌─────────┴──────────┐  sync whole list and counts table           └────────▲─────────┘
│ browser extension  │───────────────▶ directory                            │
│  core + adapters   │──────────────────────────────────────────────────────┘
└────────────────────┘  reads the page it is shown
```

## The interfaces

| Interface | Defined in | Implementations here | Used by |
|---|---|---|---|
| `IssuerApi`, `DirectoryApi` | `pop-protocol::api` | `HttpClient` | holder, directory |
| `Transport` (how `HttpClient` reaches a server) | `pop-protocol::http` | `Direct`, `Oblivious` (in `pop-ohttp`, through a relay) | holder |
| `Platform` | `pop-protocol::platform` | `MockFeed`, `Bluesky` | holder, directory |
| `IdentityProvider` | `pop-idp` | `OidcProvider`, `StaticProvider` | issuer |
| `UniquenessService` | `pop-protocol::uniqueness` | `HmacUniqueness` (in `pop-issuer`), `ThresholdUniqueness` (in `pop-uniqueness`) | issuer |
| `Store` | `pop-storage` | `MemoryStore`, `JsonFileStore` | issuer, directory |
| `WalletStore` | `pop-holder::wallet` | `FileWallet`, `MemoryWallet` | holder |
| proof system | `pop-crypto::ProofSystem` | LegoGroth16, Bulletproofs | everything, through `Scheme` |
| extension adapter | `extension/src/core.js` | `mockfeed.js`, `bluesky.js` | extension core |

## Dependency rules

These hold today (check with `cargo tree`), and a change that breaks one is a design change:

1. `pop-crypto` depends on no other crate of this repository and does no I/O.
2. `pop-protocol` depends only on `pop-crypto`.
3. `pop-holder` depends only on `pop-crypto` and `pop-protocol`. It has never heard of an identity
   provider, a database, HTTP servers or any particular platform.
4. `pop-issuer` does not depend on `pop-directory`, on any platform crate or on any concrete identity
   provider. `pop-directory` does not depend on `pop-issuer`, `pop-idp` or any platform crate.
5. Platform crates depend only on `pop-protocol`. They do not depend on each other.
6. `pop-mock-idp` and `pop-mockfeed` depend on nothing in this repository. They are ordinary servers that
   happen to be fake.
7. `pop-uniqueness` depends only on `pop-crypto` and `pop-protocol`. The issuer does not depend on it:
   it sees the `UniquenessService` trait and nothing else.
8. Only `pop-cli` names concrete implementations (`crates/pop-cli/src/wiring.rs`).
9. `pop-ohttp` (relay, gateway, client) depends only on `pop-protocol`. No server and not the holder
   depend on it: `pop-cli` puts the gateway in front of a server's routes and gives the holder an
   `Oblivious` transport ([relay.md](relay.md)).

The extension follows the same split: `core.js` knows no site's markup, each file in `adapters/` knows
one site and nothing about the directory or the holder app, and `background.js` is the only file that
touches the network (with `ohttp.js` for requests through a relay).

## Flows

**Enrol.** Holder `enrol_start` → issuer opens a session and returns the provider's login URL. The person
logs in; the provider redirects to the issuer's callback; the issuer exchanges the code, computes the
deduplication key, discards the identity code, and shows a 6-digit code in the browser. The holder sends
its commitment and the 6-digit code; the issuer signs blindly; the witness key signs the new revocation
handle.

**Bind.** The holder proves "I hold a valid, unrevoked credential; this is my pseudonym for slot i on this
platform; these are my badge tags for the next four quarters", with the platform, account id and a nonce
in the challenge. The directory verifies and stores the claim. The code is a hash of platform, account id
and pseudonym, so it points at exactly one claim.

**Badge.** The extension downloads all claims of a platform. A claim earns a badge when its code was seen
on the account: by the directory (where the platform has a public read interface) or by the extension on
the profile page.

**Like.** The holder proves "valid, unrevoked credential, counted from a day no later than the cutoff;
this is my tag for this post". The cutoff is today, or the alarm cutoff while many "it wasn't me"
reports are coming in; a first enrolment counts from its own week, a replaced secret after forty weeks. The directory
stores the tag; a second report with the same tag does not count.

**Renew, revoke.** As in design v2 §4.6: blind renewal against a proof; revocation by the holder's own
request, signed with the guardian key.

**Re-check, backup, replace.** Every two years the person logs in again and the holder shows its handle
inside a renewal proof; the issuer signs the same secret for two more years. A backup is the wallet
encrypted under a paper code, stored as ciphertext. A lost secret is replaced after an eID login: at
once with the old guardian key, otherwise after a wait in which a re-check with the old app cancels
it; the new secret starts a fresh probation. A person whose identity someone else enrolled reports it:
the other secret is revoked at once, and the first report in two years gives a new secret at once
that counts after a week; for 90 days the replaced secret can block it with a re-check. See [recovery.md](recovery.md).

## What the prototype leaves out

Compared with design v2 and the voluntary-app report: a threshold issuer, the public witnessed log,
delays and cover traffic in the relays, the desk for disputed takeovers, split backups and passkey-wrapped
backup keys (the prototype has the paper code only), hardware-wrapped secrets, phone apps, Bluesky
labels and feed generator. Each has a seam where it would go; the docs name it.
