# Using a real identity provider

The issuer learns who is enrolling through one trait, `pop_idp::IdentityProvider`:

```rust
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, IdpError>;
    async fn complete(&self, code: &str, nonce: &str) -> Result<VerifiedIdentity, IdpError>;
}
```

`VerifiedIdentity` carries the provider's name, a country code, a level of assurance and `subject`: a
lifelong identifier, unique per person. Nothing else in the system changes when the provider changes.

## Case 1: a provider that speaks OpenID Connect (most brokers)

No code is needed. The local mock is an OpenID Connect provider, and the issuer already talks to it
through the generic client `pop_idp::oidc::OidcProvider`. Switching to a real broker is a configuration
file.

1. **Sign a contract with a broker** of the Finnish Trust Network and register a client. You get an
   issuer URL, a client id and a client secret. Register the redirect address
   `https://<your issuer host>/v1/enrol/callback`.
2. **Find three things in the broker's documentation.** They differ between brokers, so do not guess:
   - the scope that releases the personal identity code,
   - the name of the ID-token claim that carries it,
   - the `acr` values it returns and what level of assurance each means.
3. **Write the configuration** (start from `examples/issuer.broker.example.json`):

```json
{
  "data_dir": "/var/lib/pop/issuer",
  "scheme": { "proof_system": "LegoGroth16", "tree_depth": 12, "slots": 3, "bp_gens_log2": 14 },
  "provider_code": 2,
  "oidc": {
    "name": "ftn-broker",
    "issuer": "https://<from the broker>",
    "client_id": "<from the broker>",
    "client_secret": "<from the broker>",
    "redirect_uri": "https://issuer.example.org/v1/enrol/callback",
    "scopes": "openid <scope for the identity code>",
    "subject_claim": "<claim that holds the identity code>",
    "country": 246,
    "acr_map": { "<acr value for bank ID>": "substantial" },
    "acr_values": "<optional: acr to request>",
    "min_loa": "substantial"
  }
}
```

4. **Run** `pop issuer --config issuer.json --listen 127.0.0.1:4002` behind your TLS reverse proxy.

What the generic client checks: discovery document matches the configured issuer; all endpoints are
https; the ID token is signed with a key from the provider's JWKS using an asymmetric algorithm; issuer,
audience, expiry and nonce match; the level of assurance is at least `min_loa`.

Points to settle before real use:

- **`subject_claim` must be lifelong.** Many providers put a pairwise or per-login value in `sub`. That
  would let one person enrol again and again. Use the claim with the national identifier.
- **`provider_code`** is signed into every credential (attribute e). Publish the list of codes and never
  reuse one. The mock uses 1.
- **Level of assurance.** Design v2 asks for "high" at enrolment. Finnish bank IDs are "substantial", so
  a pilot on bank IDs runs one level lower. `min_loa` is where that decision lives.
- **The identity code** reaches the issuer process, is fed to the keyed hash and dropped. It is never
  stored or logged. Keep it that way if you change `service.rs`: the Finnish Data Protection Act allows
  processing the code with consent but says it must not be entered into documents unnecessarily.
- **Client authentication.** The client sends the secret in the token request body
  (`client_secret_post`). If the broker requires `private_key_jwt` or mutual TLS, that is Case 2.
- **Enrolment over a phone.** The prototype shows a 6-digit code in the browser that the person types
  into the app. A phone app should use an app link back into the app instead.

## Case 2: something that is not OpenID Connect

Examples: an EUDI wallet presentation (OpenID4VP), SAML, a chip-reading app, a broker that needs
`private_key_jwt`.

1. Create a crate `pop-idp-<name>` that depends on `pop-idp` only.
2. Implement `IdentityProvider`. `authorization_url` returns where the person's browser or wallet goes;
   `state` must come back to the issuer's callback as the `state` query parameter, and `nonce` must be
   bound into the provider's signed response. `complete` receives the `code` query parameter of the
   callback and must verify the provider's signature before returning.
3. In `crates/pop-cli/src/wiring.rs`, build your provider in `build_issuer` instead of `OidcProvider`
   (add a field to `IssuerFile` to choose).

Rules every implementation must keep:

- Return an identity only after verifying a signature from the provider. Never trust a value that came
  through the browser.
- `subject` must be the same string for the same person every time, and different for different people.
- Reject anything below the configured level of assurance.

`StaticProvider` in `pop-idp/src/lib.rs` is the smallest example (tests only: it trusts its input).

## Several providers at once

The prototype's issuer takes one provider. To accept several (say bank ID now and the EUDI wallet from
2027), give the issuer a map from provider code to `IdentityProvider`, let `enrol/start` take the code,
and make sure all of them yield the same `subject` for the same person, otherwise one person can enrol
once per provider. That last condition is the hard part, not the code.

## Testing a new provider

Run the end-to-end tests with your provider in place of the mock where you can, and at least check by
hand: a second enrolment of the same person is refused; a login with too low an assurance level is
refused; a tampered or expired ID token is refused.
