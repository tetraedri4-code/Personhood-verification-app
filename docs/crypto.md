# Cryptography

Everything is in `crates/pop-crypto`. The public API is `src/scheme.rs`; the files under it
(`statement.rs`, `tree.rs`, `poseidon.rs`, `sigma.rs`) are the proof engine from the design-v2 benchmark
(`benchmark/pop-bench`), changed as little as possible so the benchmark's numbers still describe it.

## What is implemented, by design section

| Design v2 | Here |
|---|---|
| §4.1 attributes (s, δ, r, τ, γ, ℓ, c, γ0, e) on BLS12-381 | `IssuedAttrs`, `HolderSecrets`; issuer-known values checked against grids (`check_grid`) |
| §4.2 witness signature on each handle (Pointcheval–Sanders) | `WitnessKey::sign_handle`; every proof shows knowledge of it |
| §4.3 blind issuance | `BlindRequest::new`, `Scheme::issue_blind`, `finish_issuance` |
| §4.4 pseudonym nym = H_G("nym", P, i)^x, x = H_p("nym"; P, s, i, 0) | `prove_binding`, `verify_binding` |
| §4.5 quarterly badge tags, proof bound to the account | same proof: four tags for the quarters the lease touches |
| §4.5 probation question | γ ≤ cutoff, where γ is the Monday the secret counts from and the cutoff is today or the public alarm cutoff; optional in a binding (`probation_cleared`), required in a like (proposed change, [recovery.md §4](recovery.md)) |
| §4.6 blind renewal | `prove_renewal`, `reissue`, `finish_renewal` |
| §4.6 revocation: sorted Poseidon tree, a < r < b inside the circuit | `revtree.rs` builds real trees; the benchmark's gadget proves the path |
| report §3 row 9: like tag | `prove_like`: T = H_G("like", P, post)^x, x = H_p("like"; P, s, 0, post) |

Differences from the design, chosen for the prototype:

- One issuer key, not one per quarter and not threshold-shared.
- One cumulative revocation tree (the variant the benchmark measured as "u4"), not one per month.
- All four badge tags are public. The design sends later quarters as commitments.
- δ is range-checked at renewal (δ ≤ 4), not at issuance.
- No recovery, so no commitment C_d in the enrolment record.
- Dates are days since 1 January 2026.

## Choosing the proof system

`SchemeConfig.proof_system`, published by the issuer at `/v1/params`. Every party reads it from there.

| | LegoGroth16 (default) | Bulletproofs |
|---|---|---|
| Trusted setup | yes, one per statement | none |
| Measured in this repository's tests | binding proof 1.7 KB, like proof 1.2 KB; a binding takes about 2 s end to end in the demo | binding proof 3.7 KB, like proof 2.9 KB; slower |
| Benchmark (server core) | prove 0.7 s, verify 9 ms, 1.2 KB | prove 6–7 s, verify 0.3 s, 3 KB |
| Trust | whoever ran the setup can forge proofs | discrete logarithm only |

```sh
pop devnet --proof-system bulletproofs
```

Both run the same statements through the same code path; `cargo test -p pop-crypto` runs the whole flow
on each.

**The setup is the main thing to fix before LegoGroth16 is used for real.** `Scheme::lego_setup` is run
by the issuer alone, which can therefore forge any proof (though it still cannot link pseudonyms to
people). The fix is a multi-party ceremony per statement, or Bulletproofs.

## Adding a third proof system

The seam is the `Backend` enum in `statement.rs`: `prove` and `verify` match on it in two places each
(make the R1CS proof; check it), and `Cfg`/`Proof` carry the backend's keys and proof bytes. A new
backend needs: a way to prove the R1CS relation in `circuit`/`LegoCircuit` with Pedersen commitments to
chosen witnesses that the Schnorr part can open, an arm in each match, and its proof in
`codec::encode_proof`. Add it to `ProofSystem` and `wiring::proof_system`.

## Adding a statement

Add a variant to `StatementKind` and to the private `Stmt` enum in `scheme.rs`, describe it in `cfg_for`
(which hashes of the secret are revealed and which date ranges hold), and add `prove_x`/`verify_x`
wrappers. `cfg_for` puts every public value of the statement into the Fiat–Shamir context; keep that
true for new fields.

## What a verifier must check outside the proof

`verify_*` checks the proof against the `VerifyCtx` it is given. The caller is responsible for:

- `today` being the real date (the servers accept the prover's date within one day of their own),
- `revocation_root` being the issuer's current or previous root,
- the nonce being fresh (the directory keeps used nonces),
- for bindings: the account in `bind` being the account the claim is filed under.

## Limits

Research code on arkworks 0.4. Not constant-time: proving on a shared machine can leak the secret
through timing. No independent review. The composite protocol has no security proof yet (design §13).
