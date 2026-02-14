OW-ChCCA-KEM implementation in Go.

Reference paper:
[[PWZ2023] Lattice-based Authenticated Key Exchange with Tight Security](https://eprint.iacr.org/2023/823)

This repository uses [tuneinsight/lattigo](https://github.com/tuneinsight/lattigo) for NTT/ring arithmetic.

## Parameter Notes

The paper models the scheme with matrix dimensions `n, m, k`, modulus `q`, security parameter `lambda`, and Gaussian widths `alpha, alpha', gamma, eta`.

The implementation includes practical parameter presets and validation checks. Current defaults are engineering-oriented and may differ from strict paper settings.

## Testing

- Default test suite:
  - `go test ./...`
- Race check for KEM core path:
  - `go test -race ./pkg -run TestOwChCCAKEM_Decapsulate -count=1`
- High-parameter demonstration tests (not run by default):
  - `go test -tags highparams ./pkg -run TestCalculateParametersHighLevelDemo -v`

High-parameter tests are intentionally isolated from the default path to keep CI/local feedback fast and stable.
