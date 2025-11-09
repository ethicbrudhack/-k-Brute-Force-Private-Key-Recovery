# Δk Brute-Force Private Key Recovery — polished description

This script attempts to recover ECDSA private keys by brute-forcing small differences between two ephemeral nonces (Δk) for pairs of signatures suspected to be correlated.  
It works pairwise: for each pair of signatures `(r1, s1, z1)` and `(r2, s2, z2)` the script enumerates candidate Δk values (centered at zero), computes the implied `k1` and the resulting private key candidate `d`, then validates `d` by deriving the compressed public key and a Bech32 (`bc1…`) address. If the derived address and public key match the expected values supplied with the pair, the script reports success and terminates remaining workers.

## Key qualities
- **Parallelized** across multiple signature pairs (thread pool) for faster wall-clock search.  
- **Center-out Δk search** (`0, +1, -1, +2, -2, …`) so small differences are tried first.  
- **Compact progress logging:** prints short hex fragments of each candidate for monitoring.  
- **Robustness:** skips degenerate cases (e.g., `delta_s == 0`) and catches exceptions per candidate.

## Primary use cases
- Research on weak / non-random nonce generation in ECDSA implementations.  
- Auditing internally generated signatures to confirm or disprove nonce correlations.  
- Reproducing academic experiments on Δk-based key recovery (with explicit permission).

## How it validates a candidate
1. Compute `k1` from Δk and signature differences.  
2. Compute candidate private key `d = (s1*k1 - z1) * r1^{-1} (mod n)`.  
3. Derive the compressed public key from `d`.  
4. Encode HASH160 → Bech32 and compare with the expected address.  
5. If both public key hex and address match, report success.

## Ethical reminder
**Only run this code on data you own or for which you have explicit authorization.**  
Recovering private keys without permission is unethical and illegal. Use this script solely for research, auditing, or educational purposes.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
