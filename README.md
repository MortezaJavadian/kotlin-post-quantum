# kotlin-post-quantum

ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in pure Kotlin, with the FIPS 202 Keccak layer they stand on.
No native library, no JCA provider, no Android dependency — a plain JVM jar that runs anywhere Java 8
bytecode runs, Android included. The only imports outside `kotlin.*` and `java.lang` in the whole
source set are `java.math.BigInteger` and `java.security.SecureRandom`; the app it was written for
ships it at `minSdkVersion 24`.

It is a port of [paulmillr/noble-post-quantum](https://github.com/paulmillr/noble-post-quantum),
following that implementation's structure closely enough that the two can be diffed byte for byte.

> **Status: not yet validated in this repository.** The code is in production use in the app it was
> written for, and every operation that app performs is pinned there against committed vectors. What
> has not happened *here* is the NIST ACVP suite — that is the next commit series, and until it lands
> you should treat this repo as unverified. See [Validation](#validation).

## Why this exists when the JDK has both

JDK 24 added ML-KEM and ML-DSA to the platform ([JEP 496][jep496], [JEP 497][jep497]). If you are on
JDK 24 or newer and your use is ordinary — generate a keypair, encapsulate, sign, verify — use the
JDK. It is faster and it is maintained by people whose job that is.

This library exists for three cases the platform does not cover:

- **Android.** Not there. Not through API 36. Android 17 is expected to expose ML-DSA-65/87 through
  the Keystore, hardware-backed and therefore with non-exportable keys, and no ML-KEM at all. Any app
  with a `minSdkVersion` below that ships its own implementation or ships nothing.
- **Raw K-PKE.** `kpkeKeygen`/`kpkeEncrypt`/`kpkeDecrypt` are exposed as their own layer, and
  `kpkeEncrypt` takes the 32-byte coin seed from the caller. No JCA provider offers this; the KEM
  interface deliberately hides it. If you need a *reproducible* lattice encryption — the same
  plaintext and seed giving the same ciphertext — you need the layer underneath the KEM.
- **Seeded keygen with exportable keys.** `keygen(seed)` is deterministic and hands back the secret
  key as bytes. That is exactly what a Keystore-backed provider is designed to prevent.

If none of those three describe you, prefer the JDK.

[jep496]: https://openjdk.org/jeps/496
[jep497]: https://openjdk.org/jeps/497

## What is in it

| | |
|---|---|
| `pq.core` | Keccak-f[1600], SHA3-256/512, SHAKE-128/256, a seekable XOF, byte helpers |
| `pq.lattice` | The shared CRYSTALS ring — NTT, modular reduction, bit packing |
| `pq.mlkem` | K-PKE and ML-KEM / FIPS 203 |
| `pq.mldsa` | ML-DSA / FIPS 204 |

Parameter sets are constructor arguments, so all six are reachable: ML-KEM-512/768/1024 via
`MlKem(k, eta1, eta2, du, dv)` and ML-DSA-44/65/87 via `MlDsa(...)`. Only `mlKem1024` and `mlDsa87`
are declared as ready-made instances today, because those are the two the originating app ships.

### Not a public API yet

Every declaration is `internal`. That is inherited from the app this came out of, where nothing
outside the module was meant to reach the primitives directly, and it means **a consumer taking this
as a dependency cannot currently call anything.** The test source set can, which is why the ACVP work
is unblocked, but a public facade is required before the library is usable from outside. It is
deliberately not being added in the same commits that move the code, so that the move stays a pure
relocation and any behavioural change is its own reviewable diff.

## Build

```bash
./gradlew build
```

JDK 17 or newer to build; Java 8 bytecode out. The Gradle wrapper is committed, so a fresh clone
needs no Gradle installed.

## Validation

The point of this repository is that these primitives are protocol-visible: two implementations that
disagree by one byte do not interoperate, and a signature scheme that is subtly wrong still returns
`true` on its own signatures. So correctness here means agreement with NIST's own vectors, not
self-consistency.

Planned, mirroring how noble-post-quantum tests itself:

- ACVP vectors from [`usnistgov/ACVP-Server`][acvp], pinned to a tagged revision — `ML-KEM-keyGen`,
  `ML-KEM-encapDecap`, `ML-DSA-keyGen`, `ML-DSA-sigGen`, `ML-DSA-sigVer`, plus SHA3 and SHAKE
- A loader joining `prompt.json` to `expectedResults.json` by `tcId`, so no expected value is ever
  computed by the code under test
- Every parameter set, not only the two the app ships
- Skipped groups counted and reported, so a suite that silently matched nothing cannot pass

The full vector set is on the order of a gigabyte and is not vendored here. `scripts/fetch-vectors.sh`
will do a pinned shallow sparse checkout with SHA-256 verification, and a small committed subset will
keep `./gradlew test` meaningful offline.

[acvp]: https://github.com/usnistgov/ACVP-Server

## License

MIT. Because this is a derivative work of noble-post-quantum, which is also MIT, the upstream
copyright notice travels with the code — see [LICENSE](LICENSE).
