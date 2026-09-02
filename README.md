# kotlin-post-quantum

Auditable, dependency-free Kotlin implementation of NIST post-quantum cryptography.

- 🔒 Auditable: small enough to read end to end, one commit per package, no reflection, no codegen
- 🪶 Minimal: zero dependencies. The only imports outside `kotlin.*` are `java.math.BigInteger` and
  `java.security.SecureRandom`
- 🔍 Reliable: 26,467 assertions against NIST's own ACVP vectors and Project Wycheproof
- 🦾 ML-KEM & CRYSTALS-Kyber: lattice-based KEM from [FIPS 203][fips203]
- 🔋 ML-DSA & CRYSTALS-Dilithium: lattice-based signatures from [FIPS 204][fips204]
- 🧱 FIPS 202 included: Keccak-f[1600], SHA3-256/512, SHAKE-128/256 and a seekable XOF, validated
  against ACVP in their own right
- 🤖 Android from API 21: plain Java 8 bytecode, no NDK, no JCA provider, no Play Services

> [!IMPORTANT]
> This library has not been independently audited — see [Security](#security).

### This library is a port of noble-post-quantum

It follows [paulmillr/noble-post-quantum](https://github.com/paulmillr/noble-post-quantum) closely
enough that the two can be read side by side: same decomposition, same coder abstraction, same
rejection-sampling structure, same names where Kotlin allows them. The test suite is a port of
noble's too — the same ACVP and Wycheproof files, walked the same way — because a port whose tests
are its own invention proves only that it agrees with itself.

Where it differs, it differs on purpose:

| | noble-post-quantum | this |
|---|---|---|
| Schemes | ML-KEM, ML-DSA, SLH-DSA, Falcon, hybrids | ML-KEM, ML-DSA |
| Hashing | `@noble/hashes` | its own FIPS 202, with its own ACVP suite |
| Signing extras | `prehash` (HashML-DSA), `externalMu` | not implemented — [see below](#what-is-not-covered) |
| Dependencies | 3 | 0 |

## Usage

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.github.mortezajavadian:kotlin-post-quantum:0.1.0")
}
```

```xml
<!-- pom.xml -->
<dependency>
  <groupId>io.github.mortezajavadian</groupId>
  <artifactId>kotlin-post-quantum</artifactId>
  <version>0.1.0</version>
</dependency>
```

Kotlin 2.0 or newer, or any JVM language — the artifact is plain Java 8 bytecode with no Kotlin-only
signatures on the public surface. The only transitive dependency is `kotlin-stdlib`.

- [ML-KEM / Kyber](#ml-kem--kyber-shared-secrets)
- [ML-DSA / Dilithium](#ml-dsa--dilithium-signatures)
- [K-PKE: the layer under the KEM](#k-pke-the-layer-under-the-kem)
- [FIPS 202: SHA3 and SHAKE](#fips-202-sha3-and-shake)
- [What should I use?](#what-should-i-use)
- [What is public, and what is not](#what-is-public-and-what-is-not)
- [Build](#build)
- [Security](#security)
- [Testing](#testing)
- [Sizes](#sizes)
- [License](#license)

### ML-KEM / Kyber shared secrets

```kotlin
import io.github.mortezajavadian.pq.mlkem.mlKem1024   // and mlKem512, mlKem768

val kem = mlKem1024                       // or MlKem(k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4)
val alice = kem.keygen()                  // keygen(seed) takes a 64-byte seed and is deterministic
val sealed = kem.encapsulate(alice.publicKey)
val aliceShared = kem.decapsulate(sealed.cipherText, alice.secretKey)
// sealed.sharedSecret == aliceShared

// Warning: can be MITM-ed
val mallory = kem.keygen()
val malloryShared = kem.decapsulate(sealed.cipherText, mallory.secretKey)  // no exception!
// malloryShared != aliceShared
```

Lattice-based key encapsulation, defined in [FIPS 203][fips203]
([website](https://www.pq-crystals.org/kyber/resources.shtml),
[repo](https://github.com/pq-crystals/kyber)).

1. *Alice* generates a key pair and sends `publicKey` to *Bob*
2. *Bob* encapsulates against it, keeps `sharedSecret`, sends `cipherText`
3. *Alice* decapsulates and now holds the same secret, never sent in plaintext

> [!WARNING]
> Unlike ECDH, a KEM does not tell you who sent the ciphertext. A ciphertext produced under a
> different public key does not raise — `decapsulate` returns `J(z ‖ c)`, a different secret that is
> indistinguishable from a real one. Authenticate the transcript separately. ML-KEM is also
> probabilistic and rests on the quality of `SecureRandom`.

`encapsulate` applies FIPS 203 §7.2's input check to the encapsulation key: every 12-bit coefficient
must be below `q = 3329`, and a key that fails throws rather than producing a secret nobody else
derives. `decapsulate` applies §7.3's — it verifies the `H(ek)` embedded in the decapsulation key,
and deliberately does not verify `z`.

### ML-DSA / Dilithium signatures

```kotlin
import io.github.mortezajavadian.pq.mldsa.mlDsa87   // and mlDsa44, mlDsa65

val dsa = mlDsa87
val keys = dsa.keygen()                   // keygen(seed) takes a 32-byte seed
val msg = "hello".encodeToByteArray()
val sig = dsa.sign(msg, keys.secretKey)
val ok = dsa.verify(sig, msg, keys.publicKey)
```

Lattice-based signatures, defined in [FIPS 204][fips204]
([website](https://www.pq-crystals.org/dilithium/index.shtml),
[repo](https://github.com/pq-crystals/dilithium)).

`sign` and `verify` take two more arguments:

```kotlin
val context = byteArrayOf(1, 2, 3)
val sigCtx = dsa.sign(msg, keys.secretKey, context)          // verify needs the same context
val sigDet = dsa.sign(msg, keys.secretKey, extraEntropy = ByteArray(32))  // deterministic
```

- `context` — domain separation, up to 255 bytes; must match between `sign` and `verify`, and 256
  bytes throws rather than being truncated
- `extraEntropy` — the per-signature `rnd`. Left `null` it is 32 fresh random bytes (hedged signing,
  the default); 32 zero bytes gives FIPS 204 §3.4's deterministic variant. A verifier cannot tell

`sign`/`verify` operate on `0x00 ‖ len(ctx) ‖ ctx ‖ msg`, FIPS 204 §5's external API. `signInternal`
and `verifyInternal` sign the bare bytes and are what the ACVP `internal` interface vectors drive;
use them only if you are implementing that interface yourself.

### K-PKE: the layer under the KEM

```kotlin
val keys = kem.kpkeKeygen(seed)                                   // 32-byte seed
val ct = kem.kpkeEncrypt(keys.publicKey, plaintext32, coins32)    // caller supplies the coins
val pt = kem.kpkeDecrypt(ct, keys.secretKey)
```

FIPS 203's internal public-key encryption scheme, exposed rather than hidden. `kpkeEncrypt` takes the
32-byte randomness from the caller, so the same `(publicKey, plaintext, coins)` always yields the same
ciphertext. No JCA provider offers this — the KEM interface exists precisely to take the coins away —
and a reproducible lattice encryption is occasionally exactly what a protocol needs.

> [!WARNING]
> K-PKE is IND-CPA only. It is not CCA-secure, it has no implicit rejection, and a malformed
> ciphertext decrypts to garbage instead of failing. Use ML-KEM unless you know why you are not.

### FIPS 202: SHA3 and SHAKE

```kotlin
import io.github.mortezajavadian.pq.core.Sha3

val digest = Sha3.hash256(data)                    // SHA3-256
val long = Sha3.hash512(data)                      // SHA3-512
val squeezed = Sha3.shake256Of(data, dkLen = 137)  // SHAKE-256, any output length
val xof = Sha3.xof128(seed)                        // seekable: xof.seek(j, i) for matrix expansion
```

Keccak-f[1600] with the FIPS 202 padding rules, written for this library rather than borrowed.
`xof128`/`xof256` add the two-byte-suffixed, seekable form that `ExpandA` and `ExpandMask` need —
absorbing `ρ ‖ j ‖ i` without re-absorbing `ρ`, which is where a naive implementation spends most of
its time.

### What should I use?

**If you are on JDK 24 or newer and your needs are ordinary, use the JDK.** ML-KEM and ML-DSA are in
the platform ([JEP 496][jep496], [JEP 497][jep497]); it is faster and maintained by people whose job
that is.

Reach for this library in the three cases the platform does not cover:

- **Android.** Not there, not through API 36. Android 17 is expected to expose ML-DSA-65/87 through
  the Keystore — hardware-backed, so with non-exportable keys — and no ML-KEM at all. An app with a
  `minSdkVersion` below that ships its own implementation or ships nothing.
- **Raw K-PKE with caller-supplied coins.** See above. No provider exposes it.
- **Seeded keygen with exportable keys.** `keygen(seed)` is deterministic and returns the secret key
  as bytes, which is exactly what a Keystore-backed provider is built to prevent.

### What is public, and what is not

All six standardised parameter sets ship as ready-made instances, and those are the intended entry
points: `mlKem512`, `mlKem768`, `mlKem1024`, `mlDsa44`, `mlDsa65`, `mlDsa87`. The test suite drives
these exact objects with NIST's files, not copies rebuilt from the same table — otherwise the vectors
would prove the constructors are parameterised while saying nothing about the six values you get.

The published surface is five types: `MlKem`, `MlDsa`, `Sha3`, `Keccak` and `Bytes` (`EMPTY`, `equal`,
`clean`). Everything else is `internal`, and each exclusion is a specific hazard rather than tidiness:

- **The NTT rings** — `KyberRing`, `DilithiumRing`, `Crystals`. Their `zetas` table is an `IntArray`
  on a process-wide singleton. A public one is globally writable, and one changed twiddle factor
  silently corrupts every later transform in the process, in every scheme, with no exception raised
- **The bit-packing layer** — `BitPacker`, `IntCoder` and the coders. `decode`'s index arithmetic is
  unguarded because every caller inside the library is a fixed-shape loop, and `IntCoder` is an
  interface a third party could implement and hand back, which is a hook into the encoding of keys
- **`Keccak`'s constructor** — reachable only through `Sha3.sha3_256()`/`sha3_512()`/`shake128()`/
  `shake256()`. The four parameters are not independent: a rate of 0 makes `update` spin forever, one
  above 200 runs off the 25-lane state, and a SHAKE suffix without the XOF flag is a sponge no other
  implementation agrees with. `writeInto` is private for the same reason — it squeezes past the length
  the digest was built for
- **`MlDsa`'s constructor** — four of its ten numbers are fixed across every standardised set and
  `gamma2` must be one of two values that cannot be named from outside; a wrong one selects a
  *different scheme* rather than a misconfigured one. `MlKem`'s constructor is public because FIPS 203
  Table 2's five parameters really are five free numbers, but it is unvalidated: `dv = 5` where the
  set says 4 is a self-consistent scheme that interoperates with nothing
- **`encapsulate(publicKey, msg)`** — `msg` is the 32 bytes of *randomness* that determine the shared
  secret outright, and nothing in the name says so. `encapsulate(pk, "a 32-byte string".toByteArray())`
  round-trips perfectly and hands the session key to whoever guesses the string
- **`Bytes.random`** — with its `SecureRandom` private. See [Security](#security): there is no seam to
  substitute the randomness, and publishing `Bytes` does not add one

`src/main` compiles under `explicitApi()`, so an addition with no visibility modifier does not compile
rather than becoming API by default. The acceptance test for all of the above is a consumer module
built with a different `-module-name` and no `-Xfriend-paths`: every snippet in this README compiles
and runs there, and each hidden entry point above fails to.

### Build

```bash
./gradlew build
```

JDK 17 toolchain, Java 8 bytecode, Gradle wrapper committed. There is nothing to configure and no
native step: `src/main` is nine files of plain Kotlin whose only non-`kotlin.*` imports are
`java.security.SecureRandom` in `core/Bytes.kt` and `java.math.BigInteger` in `lattice/Crystals.kt`.

The build also enforces two things worth knowing about before you send a patch: `explicitApi()`, so a
declaration with no visibility modifier does not compile, and `-Xjdk-release=1.8` on the published
compilation, so a call to a Java 9+ method is a compile error here instead of a `NoSuchMethodError` on
someone's Android 5 device.

### Security

Not independently audited. Do not deploy it as your only line of defence on the strength of this
README; read the code, and read [Testing](#testing) for exactly what is and is not proven.

What is deliberate:

- **Randomness** comes from one `java.security.SecureRandom` held privately in `Bytes`. There is no
  hook to replace it, which also means there is no hook for a test to weaken it
- **Secrets are wiped.** `keygen()` and `encapsulate(publicKey)` zero the randomness they generated in
  a `finally`, so an exception on the §7.2 check does not leave it in a live array, and intermediate
  polynomials are cleaned after use. On the JVM this is best-effort — a moving collector may already
  have copied the array — but the copy the library owns is cleared
- **Comparison** of secret-dependent bytes goes through `Bytes.equal`, which reads every byte and does
  not short-circuit on the first difference
- **BigInteger touches no secret.** It appears once, computing the NTT root-of-unity table at
  construction from public constants; every operation on key or message material is `Int` arithmetic
- **The dangerous surface is not published.** The mutable NTT tables, the unguarded bit-packing layer,
  `Keccak`'s raw constructor and the two entry points that take randomness for a message are all
  `internal` — see [What is public, and what is not](#what-is-public-and-what-is-not) for the reason
  behind each one

What is not claimed:

- **Not verified constant-time.** The arithmetic is written to avoid secret-dependent branches, but no
  formal or empirical timing analysis has been performed, and the JVM gives no guarantees to analyse:
  JIT, bounds-check elimination and GC all vary with things the source does not control. Assume this
  code is unsuitable where an attacker can measure your CPU
- **No side-channel hardening** beyond the above — no masking, no blinding, no fault-injection
  countermeasures
- **A KEM authenticates nobody.** See the warning under [ML-KEM](#ml-kem--kyber-shared-secrets):
  `decapsulate` cannot fail, and a ciphertext from the wrong key yields a different secret rather than
  an exception. If you need to know who you are talking to, sign the transcript

Report a vulnerability by opening an issue if it is theoretical, or through GitHub's private
vulnerability reporting on this repository if it is not.

### Testing

```bash
./scripts/fetch-vectors.sh   # 63 MB into test-vectors/ (gitignored), from one pinned commit
./gradlew test               # JUnit 5: one container per suite, one dynamic test per case
./gradlew vectors            # the same suites through main(), with per-case assertion counts
./gradlew vectors --args="SHAKE ML-DSA-87"          # …filtered
```

The vectors are the same ones noble-post-quantum runs, from the same place: a sparse, blob-filtered
checkout of [paulmillr/acvp-vectors][acvpvectors] pinned to `2e9216ce`, which carries NIST's
[ACVP-Server][acvpserver] JSON and a mirror of Project [Wycheproof][wycheproof]'s `testvectors_v1`.
They are not committed — 63 MB is the smaller reason; the larger one is that a checked-in copy is a
copy that can be edited until it agrees with the implementation.

Three environment knobs: `PQ_VECTORS` moves the vector root, `PQ_REQUIRE_VECTORS=1` turns a missing
file from *skipped* into *failed* (use it in CI), and `PQ_MAX_CASES=n` caps cases per group for a fast
pass — a cap that announces itself in the output rather than silently shrinking the run.

The current run, with `PQ_REQUIRE_VECTORS=1`:

```
62 passed, 0 failed, 0 skipped — 26467 assertions
```

7 suites, 62 cases. Two of them run no vector file — the JSON reader written for this project, because
ACVP's SHAKE prompt is hundreds of megabytes and has to be streamed rather than parsed into memory, and
the port of noble's `basic.test.ts`. The other five walk the files:

| | groups entered | cases reached |
|---|---|---|
| ACVP — 13 of 13 suites: ML-KEM, ML-DSA, SHA3, SHAKE | 52 of 74 | 8,733 of 9,019 |
| Wycheproof — 21 of 21 files | 280 of 280 | 2,839 of 2,839 |

Of the 11,572 cases reached, **4,457 produce assertions**; the remaining 7,115 are passed over for one
of the named reasons below, and every one of them is counted and printed. Each ACVP case is validated
against all three of NIST's files — `prompt.json`, `expectedResults.json` and
`internalProjection.json` — joined on `tcId`, and a `tcId` that does not appear in all three is a
failure rather than a case quietly walked past.

#### What is not covered

Every exclusion is named where it happens and counted in a `passed over (7140 occurrences)` table the
run prints before its summary. There is no category of "skipped quietly".

- **Non-byte-aligned SHA3/SHAKE lengths — 6,868 cases.** ACVP varies `len` and `outLen` in *bits* and
  most values are not multiples of 8. `Sha3` takes and returns `ByteArray`, so a 1,437-bit message is
  not expressible at the API. Not a gap against noble, which has no SHA3 suite of its own — it depends
  on `@noble/hashes`
- **External-mu signing and HashML-DSA pre-hash — 247 Wycheproof cases, plus 12 ACVP sigGen and 6
  sigVer groups (270 cases), split evenly by group between the two features.** noble implements both;
  this port implements neither, so the vectors are entered, recognised and declined by name
- **`getPublicKey(sk)` — 3 ACVP ML-DSA keyGen groups.** Those groups do run: what is dropped is the one
  assertion that re-derives the public key from the secret key, because there is no such function here.
  The vector's own `pk` is still checked against `keygen(seed)`
- **ACVP large-data tests — 4 groups, 16 cases.** LDT hashes 1–8 GiB of repeating content; it measures
  a streaming API this library does not expose
- **Two of noble's `basic.test.ts` cases.** Both replace `crypto.getRandomValues` and inspect the array
  the implementation was handed, asserting that generated randomness does not survive an error path.
  `Bytes.random` owns a private `SecureRandom` and there is deliberately no such seam, so that property
  is structural here instead — `keygen()` and `encapsulate(publicKey)` wipe in a `finally`. Adding an
  injectable RNG only to observe it would be a change to the library, not to its tests

That leaves 286 ACVP cases never reached, all of them inside the 22 groups above, and **zero unreached
Wycheproof cases** — all 21 files, all 280 groups, all 2,839 cases are walked.

#### The rules that keep it honest

A validation suite whose failure mode is *passing* is worse than none. So:

- **Assertions are counted, and a case that asserted nothing fails.** Not "warns" — fails. This is what
  catches a vector file whose shape changed upstream and now yields an empty loop
- **A missing vector file is *skipped*, never passed** — and `PQ_REQUIRE_VECTORS=1` makes it a failure
- **The suite always runs.** `test-vectors/` is not a declared Gradle input, so an up-to-date check
  would let `./gradlew test` reprint a previous run's green summary after fetching a newer pin.
  `outputs.upToDateWhen { false }` removes that possibility — and `outputs.cacheIf { false }` closes
  the second door, since `Test` is a `@CacheableTask` and the build cache is consulted *after* the
  up-to-date check fails, restoring the same false green without executing anything
- **Two front ends over one body of cases.** `./gradlew test` and `./gradlew vectors` share every suite,
  case and assertion; they can only disagree if the harness is broken

#### What the suite has already caught

One real bug, in the check that FIPS 203 §7.2 exists to perform. `compressCoder(12)` returned an
identity coder, so `ByteDecode₁₂` did not reduce modulo `q` — and §7.2's test, *encode the decode of
the encapsulation key and compare*, became a tautology that no input could fail. A key carrying a
coefficient of 3329 or above was accepted and produced a shared secret nobody else derives. Two
independent sets of vectors fail without the fix: ACVP's three `encapsulationKeyCheck` groups, whose
rejected cases give the reason *noisy linear system values too large*, and Wycheproof's 100
*Public key not reduced* cases in each of `mlkem_512/768/1024_encaps_test`. `ByteCoder12` is the fix —
one conditional subtraction — and any copy of this code taken before it needs the same two-file change.

### Sizes

ML-KEM, in bytes. The shared secret is 32 for all three, and `keygen(seed)` takes 64 (`d ‖ z`):

| | public key | secret key | ciphertext |
|---|---|---|---|
| ML-KEM-512 | 800 | 1632 | 768 |
| ML-KEM-768 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 1568 | 3168 | 1568 |

ML-DSA, in bytes. `keygen(seed)` takes 32 (`ξ`), and signature length is fixed, not variable:

| | public key | secret key | signature |
|---|---|---|---|
| ML-DSA-44 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4627 |

Source: nine Kotlin files, 2,348 lines with comments; the suite that validates them is 2,540. No
generated code, no reflection, nothing to strip in a release build.

### License

MIT, © 2026 Morteza Javadian.

A derivative work of [paulmillr/noble-post-quantum](https://github.com/paulmillr/noble-post-quantum),
MIT © 2024 Paul Miller — the decomposition, the coder abstraction and the test corpus are its ideas.
FIPS 202, 203 and 204 are public documents; CRYSTALS-Kyber and CRYSTALS-Dilithium are the work of their
respective teams.

[fips203]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
[fips204]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
[jep496]: https://openjdk.org/jeps/496
[jep497]: https://openjdk.org/jeps/497
[acvpvectors]: https://github.com/paulmillr/acvp-vectors
[acvpserver]: https://github.com/usnistgov/ACVP-Server
[wycheproof]: https://github.com/C2SP/wycheproof
