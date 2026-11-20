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
| Benchmark (server core) | prove 0.7 s, verify 9 to 11 ms, 1.2 KB | prove 6–7 s, verify 0.2 to 0.3 s, 3 KB |
| Trust | whoever ran the setup can forge proofs | discrete logarithm only |

```sh
pop devnet --proof-system bulletproofs
```

Both run the same statements through the same code path; `cargo test -p pop-crypto` runs the whole flow
on each.

**The setup is the main thing to fix before LegoGroth16 is used for real.** `Scheme::lego_setup` is run
by the issuer alone, which can therefore forge any proof (though it still cannot link pseudonyms to
people). The fix is a multi-party ceremony per statement, or Bulletproofs.

## Checking many like proofs at once

`Scheme::verify_likes` checks a batch of like proofs together and accepts only if every one would pass
`verify_like`; `Scheme::sieve_likes` says which ones are valid, checking halves of a failed batch (binary
search) so that false proofs cannot sink the true ones in their batch. Halving costs about
n (log2 m + 2) proofs' worth of combined checks for m false proofs among n; past 3n, the rest are
checked one by one, so a flood of false proofs costs little more than checking each alone. The issuer still checks each like
as it arrives; these are for a server that collects likes for a fraction of a second first.

How: every check whose verifier side is the same for all proofs is multiplied by a random scalar per
proof and added up, so that a false proof makes the sum non-zero except with probability about 2^-255.
The BBS pairing check becomes two pairings per batch; the Bulletproofs check one multi-scalar
multiplication for all (ark-bulletproofs `batch_verify`); the LegoGroth16 check one pairing per proof
plus three and one final exponentiation per batch. The Schnorr relations and the PS signature are
rebuilt and hashed into each proof's challenge (compact encoding), so they stay per proof. The random
scalars come from the operating system: a prover who knew them could make a false proof cancel out.

Measured on 20 November 2026 on one core of the development server, like proofs at the default settings
(tree depth 8), `cargo test --release -p pop-crypto --test batch -- --ignored --nocapture --test-threads 1`:

| | One by one | Batches of 16 | Batches of 64 | Largest batch | Largest, with 1 false | with 4 false |
|---|---|---|---|---|---|---|
| Bulletproofs (largest 128) | 175 ms | 46 ms | 40 ms | 39 ms (4.5x) | 44 ms | 59 ms |
| LegoGroth16 (largest 512) | 10.7 ms | 8.8 ms | 8.3 ms | 7.9 ms (1.3x) | 8.6 ms | 8.9 ms |

Per proof. For LegoGroth16 about 6 ms of the 8 is the per-proof Schnorr and PS work; sending the Schnorr
commitments instead of the challenge, and a BBS signature instead of PS for the handle, would make those
combinable too (not built).

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
