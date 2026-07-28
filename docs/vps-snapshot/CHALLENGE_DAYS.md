# Challenge day log

Generated: 2026-07-13T06:05:48.471247Z

## Day 3 — DAY3_PASS

- date: 2026-07-12
- author: lambda0xE
- source: https://x.com/lambda0xE/status/2076417278543835438
- title: Timing / constancy probes on Apple Silicon
- unlock_signal: **False**

Built pvac on Apple Silicon (-march=armv8-a+crypto). Benchmarks: prf_R ~15.3 ms; enc_value ~43.4 ms (2 layers / 37 edges). Constancy (independent keys, 7 runs): skA 44.07 ms vs skB 41.90 ms statistically equal → no sk-dependent timing branch. No remote-relevant leak. No exploit path from timing.

**Closed paths:**

- sk-dependent timing side channel (Apple Silicon build / this probe)
- remote-relevant timing exploit from these constancy results

**Next:**

- Day 4–5 algebraic / reduced-params notes
- Day 7 freeze if nothing simplifies

**Lab action:** Do NOT spend VPS time on timing attacks against public package. Keep unlock sensors + wire/mask/LPN/lexicon. Watch Day 4–5 algebra posts.
