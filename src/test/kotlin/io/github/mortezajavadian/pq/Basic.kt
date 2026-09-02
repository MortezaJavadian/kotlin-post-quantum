package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.core.Bytes
import io.github.mortezajavadian.pq.core.Sha3
import io.github.mortezajavadian.pq.mldsa.MlDsa
import io.github.mortezajavadian.pq.mlkem.MlKem
import io.github.mortezajavadian.pq.testing.Check
import io.github.mortezajavadian.pq.testing.Suite
import io.github.mortezajavadian.pq.testing.suite

/**
 * The port of `noble-post-quantum/test/basic.test.ts`.
 *
 * These are the behavioural tests, and they cover what the vector suites structurally cannot. An
 * ACVP file says what `Decaps` must return; it does not say that `decapsulate` must leave its
 * arguments alone, or that a ciphertext with one bit flipped must return an unpredictable secret
 * rather than throwing, or that `verify` must answer `false` instead of raising when a signature's
 * hint field is corrupt. Every one of those is a property some real implementation has got wrong.
 *
 * The reference file has more cases than this. Everything omitted is omitted because it tests
 * JavaScript, not the algorithm — prototype-pollution of an options object, frozen key lists in
 * `validateSigOpts`, `copyBytes` — or because it tests a scheme this library does not implement
 * (SLH-DSA, Falcon, the hybrid suites). The three genuinely missing *features* are `prehash`,
 * `externalMu` and an ML-DSA `getPublicKey`; those are reported as skips by the vector suites, where
 * NIST has vectors for them, rather than pretended at here.
 *
 * Two reference cases are omitted for a reason worth naming rather than filing under "JavaScript":
 * `ML-KEM wipes generated randomness when encapsulation throws` and `ML-DSA prepares and cleans
 * entropy before secret expansion` both work by replacing `crypto.getRandomValues` and inspecting the
 * array the implementation was handed. `Bytes.random` owns a private `SecureRandom` and there is no
 * such seam here, so the half of each property that needs the seam — that generated randomness does
 * not survive an error path — is structural in this port instead: `keygen()`, `encapsulate(publicKey)`
 * and `signInternal` all wipe what they generated before rethrowing. Adding an injectable RNG purely
 * to observe it would be a change to the library, not to its tests, so that half is left as a stated
 * gap. The half that needs no seam *is* tested, by `ML-DSA validates entropy before it expands the
 * key`: the guard order those cases pin is observable from outside, because with both a bad `rnd` and
 * a bad key it decides which of the two errors the caller sees.
 */
internal val basicSuite: Suite = suite("basic") {

    /**
     * A key API must not consume its inputs.
     *
     * This library wipes aggressively — that is the point of `Bytes.clean` — and wiping is exactly
     * how a caller's own seed, secret key or message ends up zeroed under it. Every internal wipe
     * must therefore land on a copy, and the only way to know it does is to hash the caller's bytes
     * before and after. The reference suite checks the same eight calls.
     */
    test("ML-KEM does not mutate its arguments") {
        for ((level, kem) in Params.kemLevels) {
            val at = "ML-KEM-$level"
            val seed = Bytes.random(64)
            val seedBefore = seed.copyOf()
            val keys = kem.keygen(seed)
            unchanged(seed, seedBefore, "$at keygen seed")

            val secretBefore = keys.secretKey.copyOf()
            Check.eq(kem.publicKeyOf(keys.secretKey), keys.publicKey, "$at publicKey inside secretKey")
            unchanged(keys.secretKey, secretBefore, "$at publicKeyOf secretKey")

            val msg = Bytes.random(32)
            val msgBefore = msg.copyOf()
            val publicBefore = keys.publicKey.copyOf()
            val sealed = kem.encapsulate(keys.publicKey, msg)
            unchanged(msg, msgBefore, "$at encapsulate message")
            unchanged(keys.publicKey, publicBefore, "$at encapsulate publicKey")

            val cipherBefore = sealed.cipherText.copyOf()
            val shared = kem.decapsulate(sealed.cipherText, keys.secretKey)
            unchanged(sealed.cipherText, cipherBefore, "$at decapsulate cipherText")
            unchanged(keys.secretKey, secretBefore, "$at decapsulate secretKey")
            Check.eq(shared, sealed.sharedSecret, "$at round-trip shared secret")
        }
    }

    test("ML-DSA does not mutate its arguments") {
        for ((level, dsa) in Params.dsaLevels) {
            val at = "ML-DSA-$level"
            val seed = Bytes.random(32)
            val seedBefore = seed.copyOf()
            val keys = dsa.keygen(seed)
            unchanged(seed, seedBefore, "$at keygen seed")

            val msg = Bytes.random(32)
            val entropy = Bytes.random(32)
            val msgBefore = msg.copyOf()
            val entropyBefore = entropy.copyOf()
            val secretBefore = keys.secretKey.copyOf()
            val sig = dsa.sign(msg, keys.secretKey, Bytes.EMPTY, entropy)
            unchanged(msg, msgBefore, "$at sign message")
            unchanged(entropy, entropyBefore, "$at sign extraEntropy")
            unchanged(keys.secretKey, secretBefore, "$at sign secretKey")

            val sigBefore = sig.copyOf()
            val publicBefore = keys.publicKey.copyOf()
            Check.ok(dsa.verify(sig, msg, keys.publicKey), "$at signature verifies")
            unchanged(sig, sigBefore, "$at verify signature")
            unchanged(keys.publicKey, publicBefore, "$at verify publicKey")
            unchanged(msg, msgBefore, "$at verify message")
        }
    }

    /**
     * FIPS 203 §7.2's input check: every 12-bit coefficient of an encapsulation key must be `< q`.
     *
     * The key is not a hash of anything, so nothing else catches a value out of range — the scheme
     * would keep working and produce a shared secret that does not interoperate. The library
     * re-encodes the decoded key and compares, which rejects exactly the non-canonical encodings.
     *
     * The literal seed `1, 2, 3, …` comes from the reference test so the key being corrupted is the
     * same key there; the byte surgery sets coefficient 0 to `0x0fff = 4095`, since the packing is
     * little-endian 12-bit and the coefficient's low eight bits are byte 0 with its top four in the
     * low nibble of byte 1.
     */
    test("ML-KEM rejects a coefficient above q−1") {
        for ((level, kem) in Params.kemLevels) {
            val at = "ML-KEM-$level"
            val seed = ByteArray(64) { (it + 1).toByte() }
            val keys = kem.keygen(seed)
            val msg = ByteArray(32) { 1 }
            val bad = keys.publicKey.copyOf()
            bad[0] = 0xff.toByte()
            bad[1] = ((bad[1].toInt() and 0xf0) or 0x0f).toByte()
            Check.throwsWith("wrong publicKey modulus", "$at coefficient 4095") {
                kem.encapsulate(bad, msg)
            }
        }
    }

    /**
     * The boundary itself: `q = 3329` must be rejected and `q − 1 = 3328` accepted.
     *
     * An off-by-one in a range check is the mistake this catches, and it is a mistake that would pass
     * every ACVP vector — NIST does not generate a key whose first coefficient is exactly 3328.
     */
    test("ML-KEM accepts q−1 and rejects q") {
        for ((level, kem) in Params.kemLevels) {
            val at = "ML-KEM-$level"
            val keys = kem.keygen(ByteArray(64) { (it + 1).toByte() })
            val msg = ByteArray(32) { 1 }

            val atModulus = keys.publicKey.copyOf()
            atModulus[0] = 0x01
            atModulus[1] = ((atModulus[1].toInt() and 0xf0) or 0x0d).toByte()
            Check.throwsWith("wrong publicKey modulus", "$at coefficient q") {
                kem.encapsulate(atModulus, msg)
            }

            val belowModulus = keys.publicKey.copyOf()
            belowModulus[0] = 0x00
            belowModulus[1] = ((belowModulus[1].toInt() and 0xf0) or 0x0d).toByte()
            val sealed = kem.encapsulate(belowModulus, msg)
            Check.eq(sealed.cipherText.size, kem.cipherTextLen, "$at coefficient q−1 accepted")
        }
    }

    /**
     * `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`, and the two trailing fields are checked very differently.
     *
     * `H(ek)` is verified — a decapsulation key whose embedded hash does not match its embedded
     * encapsulation key is not a key, and FIPS 203 §7.3's input check says to reject it. `z` is not
     * verified and must not be: it only ever feeds the implicit-rejection branch, so a corrupted `z`
     * still decapsulates a *valid* ciphertext to the correct secret. An implementation that hashed
     * the whole key and compared would break that, and would break it only for keys it had not
     * generated itself.
     */
    test("ML-KEM decapsulate checks H(ek) and ignores z") {
        for ((level, kem) in Params.kemLevels) {
            val at = "ML-KEM-$level"
            val keys = kem.keygen(Bytes.random(64))
            val sealed = kem.encapsulate(keys.publicKey)

            val badHash = keys.secretKey.copyOf()
            val hashAt = badHash.size - 96 + 32
            badHash[hashAt] = (badHash[hashAt].toInt() xor 1).toByte()
            Check.throwsWith("hash check failed", "$at corrupted H(ek)") {
                kem.decapsulate(sealed.cipherText, badHash)
            }

            val badZ = keys.secretKey.copyOf()
            badZ[badZ.size - 1] = (badZ[badZ.size - 1].toInt() xor 1).toByte()
            Check.eq(
                kem.decapsulate(sealed.cipherText, badZ),
                sealed.sharedSecret,
                "$at corrupted z still decapsulates",
            )
        }
    }

    /**
     * Implicit rejection, asserted against its definition rather than against "it did not throw".
     *
     * A tampered ciphertext must yield `J(z ‖ c) = SHAKE256(z ‖ c, 32)`. The value is recomputed here
     * from the seed's own second half, because the property that matters is not that the output is
     * wrong — it is that the output is a *specific* pseudorandom value an attacker cannot distinguish
     * from a real secret, and is the same on every call. An implementation that returned random bytes
     * would pass a "differs from the real secret" check and be trivially detectable on the wire.
     */
    test("ML-KEM implicitly rejects a tampered ciphertext") {
        for ((level, kem) in Params.kemLevels) {
            val at = "ML-KEM-$level"
            val seed = Bytes.random(64)
            val keys = kem.keygen(seed)
            val sealed = kem.encapsulate(keys.publicKey)

            val tampered = sealed.cipherText.copyOf()
            tampered[0] = (tampered[0].toInt() xor 1).toByte()
            val rejected = kem.decapsulate(tampered, keys.secretKey)
            val z = seed.copyOfRange(32, 64)
            Check.eq(
                rejected,
                Sha3.shake256Of(Bytes.concat(z, tampered), 32),
                "$at rejection secret is J(z ‖ c)",
            )
            Check.ok(!rejected.contentEquals(sealed.sharedSecret), "$at rejection secret differs")
            Check.eq(kem.decapsulate(tampered, keys.secretKey), rejected, "$at rejection is deterministic")
        }
    }

    /**
     * Every ML-KEM input is length-checked, and each check names the argument it rejected.
     *
     * All four of these arrive from the wire in the app this came out of, so "one byte short" is a
     * shape an attacker picks, not a typo. Kotlin's types make most of the reference file's
     * `throws(() => sign(msg, sk, false))` cases unexpressible, but length is not a type: a
     * `ByteArray` of the wrong size compiles, and without the guard `publicKey` one byte short would
     * decode a coefficient vector out of whatever followed it in memory-order terms — or, worse for a
     * KEM, silently produce a shared secret nobody else derives.
     */
    test("ML-KEM rejects wrong-length inputs") {
        for ((level, kem) in Params.kemLevels) {
            val at = "ML-KEM-$level"
            val keys = kem.keygen(Bytes.random(64))
            val sealed = kem.encapsulate(keys.publicKey)
            val msg = ByteArray(32) { 1 }

            for (size in listOf(0, kem.publicKeyLen - 1, kem.publicKeyLen + 1)) {
                Check.throwsWith("publicKey", "$at encapsulate publicKey of $size bytes") {
                    kem.encapsulate(ByteArray(size), msg)
                }
            }
            for (size in listOf(0, 31, 33)) {
                Check.throwsWith("message", "$at encapsulate message of $size bytes") {
                    kem.encapsulate(keys.publicKey, ByteArray(size))
                }
            }
            for (size in listOf(0, kem.secretKeyLen - 1, kem.secretKeyLen + 1)) {
                Check.throwsWith("secretKey", "$at decapsulate secretKey of $size bytes") {
                    kem.decapsulate(sealed.cipherText, ByteArray(size))
                }
            }
            for (size in listOf(0, kem.cipherTextLen - 1, kem.cipherTextLen + 1)) {
                Check.throwsWith("cipherText", "$at decapsulate cipherText of $size bytes") {
                    kem.decapsulate(ByteArray(size), keys.secretKey)
                }
            }

            // K-PKE is exposed, so it is checked too — and it is the layer where a missing guard is
            // worst, because the coins are the ciphertext's only entropy: with predictable coins
            // anyone holding `ek` recomputes r̂, e₁, e₂ and reads the plaintext back out.
            val kpke = kem.kpkeKeygen(Bytes.random(32))
            val coins = ByteArray(32) { 2 }
            for (size in listOf(0, 31, 33, 64)) {
                Check.throwsWith("seed", "$at kpkeEncrypt seed of $size bytes") {
                    kem.kpkeEncrypt(kpke.publicKey, msg, ByteArray(size))
                }
            }
            val ct = kem.kpkeEncrypt(kpke.publicKey, msg, coins)
            Check.eq(kem.kpkeDecrypt(ct, kpke.secretKey), msg, "$at K-PKE round trip")
            for (size in listOf(0, ct.size - 1, ct.size + 1)) {
                Check.throwsWith("cipherText", "$at kpkeDecrypt cipherText of $size bytes") {
                    kem.kpkeDecrypt(ByteArray(size), kpke.secretKey)
                }
            }
            for (size in listOf(0, kem.kpkeSecretKeyLen - 1, kem.kpkeSecretKeyLen + 1)) {
                Check.throwsWith("secretKey", "$at kpkeDecrypt secretKey of $size bytes") {
                    kem.kpkeDecrypt(ct, ByteArray(size))
                }
            }
            // The full ML-KEM secret key is the second legal width: decapsulate passes it through.
            Check.eq(
                kem.kpkeDecrypt(ct, ByteArray(kem.secretKeyLen).also { kpke.secretKey.copyInto(it) }),
                msg,
                "$at kpkeDecrypt accepts the full secretKey",
            )
        }
    }

    /** A zero-length key must be rejected on length, before anything tries to decode it. */
    test("ML-DSA rejects an empty secret key") {
        for ((level, dsa) in Params.dsaLevels) {
            Check.throwsWith("secretKey", "ML-DSA-$level empty secretKey") {
                dsa.signInternal(byteArrayOf(1), Bytes.EMPTY)
            }
        }
    }

    /**
     * A key whose `s1` coefficient decodes outside `[−η, η]` is malformed, and signing with it would
     * produce a signature over the wrong secret rather than fail.
     *
     * η = 2 packs each coefficient into three bits as `η − value`, so the field can hold `5..7` —
     * values no valid key produces. The reference test uses ML-DSA-44 with the byte set to 7; ML-DSA-87
     * shares η = 2 and the same 128-byte `ρ ‖ K ‖ tr` prefix, so it is included too. ML-DSA-65 is not:
     * at η = 4 the field is four bits wide and 7 decodes to −3, which is a legal coefficient.
     */
    test("ML-DSA rejects a malformed secret key") {
        for ((level, dsa) in listOf("44" to Params.mlDsa44, "87" to Params.mlDsa87)) {
            val badKey = ByteArray(dsa.secretKeyLen)
            badKey[32 + 32 + 64] = 7
            Check.throwsWith("malformed key", "ML-DSA-$level s1 out of range") {
                dsa.signInternal(byteArrayOf(1), badKey)
            }
        }
    }

    /**
     * A corrupt signature makes `verify` return false. It must not throw.
     *
     * The signature is the attacker-controlled input, so the difference between `false` and an
     * exception is the difference between a rejected login and a crashed server. All three shapes here
     * corrupt the hint field, which is the one part of an ML-DSA signature with a non-trivial encoding:
     * `k` cumulative counters after `ω` position bytes, where the counters must not exceed ω and the
     * unused positions must be zero.
     */
    test("ML-DSA verify returns false on a malformed hint") {
        for ((dsa, omega, k) in Params.dsaHintShape) {
            val at = "ML-DSA ω=$omega"
            val keys = dsa.keygen(Bytes.random(32))
            val msg = Bytes.random(32)
            val sig = dsa.sign(msg, keys.secretKey)
            Check.ok(dsa.verify(sig, msg, keys.publicKey), "$at baseline verifies")

            val badCounter = sig.copyOf()
            badCounter[sig.size - 1] = (omega + 1).toByte()
            Check.ok(!dsa.verify(badCounter, msg, keys.publicKey), "$at counter above ω")

            // The last cumulative counter is the total number of hint positions; anything between it
            // and ω is padding that must be zero.
            val totalHints = sig[sig.size - 1].toInt() and 0xff
            if (totalHints < omega) {
                val badPadding = sig.copyOf()
                badPadding[sig.size - (omega + k) + omega - 1] = 1
                Check.ok(!dsa.verify(badPadding, msg, keys.publicKey), "$at non-zero hint padding")
            }

            val truncated = sig.copyOfRange(0, sig.size - 1)
            Check.ok(!dsa.verify(truncated, msg, keys.publicKey), "$at truncated signature")
        }
    }

    /**
     * The context string is part of what is signed, so it separates domains.
     *
     * `sign` prefixes `0x00 ‖ len(ctx) ‖ ctx`, which means a signature made under one context must
     * not verify under another and — the case that actually bites — a signature made with no context
     * must not verify under one. An implementation that forgot the envelope would pass its own
     * round-trip and fail against every other implementation.
     */
    test("ML-DSA separates signing contexts") {
        for ((level, dsa) in Params.dsaLevels) {
            val at = "ML-DSA-$level"
            val keys = dsa.keygen(Bytes.random(32))
            val msg = Bytes.random(32)
            val context = "kotlin-post-quantum".encodeToByteArray()
            val other = "kotlin-post-quantums".encodeToByteArray()

            val withContext = dsa.sign(msg, keys.secretKey, context)
            Check.ok(dsa.verify(withContext, msg, keys.publicKey, context), "$at same context verifies")
            Check.ok(!dsa.verify(withContext, msg, keys.publicKey), "$at context vs none")
            Check.ok(!dsa.verify(withContext, msg, keys.publicKey, other), "$at context vs another")

            val withoutContext = dsa.sign(msg, keys.secretKey)
            Check.ok(dsa.verify(withoutContext, msg, keys.publicKey), "$at no context verifies")
            Check.ok(!dsa.verify(withoutContext, msg, keys.publicKey, context), "$at none vs context")
        }
    }

    /**
     * A context longer than 255 bytes has no representation in the envelope's single length byte, so
     * FIPS 204 caps it and the library must refuse rather than truncate.
     */
    test("ML-DSA rejects an over-long context") {
        val dsa: MlDsa = Params.mlDsa87
        val keys = dsa.keygen(Bytes.random(32))
        Check.throws("256-byte context") { dsa.sign(byteArrayOf(1), keys.secretKey, ByteArray(256)) }
        Check.throws("256-byte context on verify") {
            dsa.verify(ByteArray(dsa.signatureLen), byteArrayOf(1), keys.publicKey, ByteArray(256))
        }
    }

    /**
     * The empty message, which the reference file uses for its whole `sign/ver opts` matrix.
     *
     * Zero-length is the input that finds a `if (msg.isEmpty())` shortcut, an absorb loop that never
     * runs, or a length prefix written from the wrong variable. It is also where the envelope earns its
     * keep: `0x00 ‖ 0x00 ‖ ""` and `0x00 ‖ 0x00 ‖ 0x00` are different messages, so a signature over
     * nothing must not verify over a zero byte.
     */
    test("ML-DSA signs an empty message") {
        for ((level, dsa) in Params.dsaLevels) {
            val at = "ML-DSA-$level"
            val keys = dsa.keygen(Bytes.random(32))
            val context = byteArrayOf(1, 2, 3)

            val sig = dsa.sign(Bytes.EMPTY, keys.secretKey)
            Check.eq(sig.size, dsa.signatureLen, "$at signature length")
            Check.ok(dsa.verify(sig, Bytes.EMPTY, keys.publicKey), "$at empty message verifies")
            Check.ok(!dsa.verify(sig, byteArrayOf(0), keys.publicKey), "$at empty is not a zero byte")

            val withContext = dsa.sign(Bytes.EMPTY, keys.secretKey, context)
            Check.ok(
                dsa.verify(withContext, Bytes.EMPTY, keys.publicKey, context),
                "$at empty message under a context",
            )
            Check.ok(
                !dsa.verify(withContext, Bytes.EMPTY, keys.publicKey),
                "$at context still separates an empty message",
            )
        }
    }

    /**
     * Hedged and deterministic signing, the reference file's `extraEntropy` cases.
     *
     * `rnd` is the one input that decides whether signing is a function. Left to the library it is 32
     * fresh bytes and two signatures over the same message differ; supplied, it pins them. FIPS-204
     * §3.4's deterministic variant is `rnd = 0³²`, which is what ACVP's `deterministic: true` groups
     * sign with — so this case is the hermetic statement of the property those vectors check by value.
     *
     * The pair that matters is the last two assertions: a verifier cannot tell the two apart, which is
     * why an implementation is free to choose, and why a *test* that only ever signed deterministically
     * would never notice an implementation that ignored `rnd` altogether.
     */
    test("ML-DSA deterministic and hedged signing") {
        for ((level, dsa) in Params.dsaLevels) {
            val at = "ML-DSA-$level"
            val keys = dsa.keygen(Bytes.random(32))
            val msg = Bytes.random(32)

            val zeros = ByteArray(32)
            val deterministic = dsa.sign(msg, keys.secretKey, Bytes.EMPTY, zeros)
            Check.eq(
                dsa.sign(msg, keys.secretKey, Bytes.EMPTY, zeros),
                deterministic,
                "$at rnd = 0³² is reproducible",
            )

            val pinned = ByteArray(32) { 0x5a }
            val hedgedPin = dsa.sign(msg, keys.secretKey, Bytes.EMPTY, pinned)
            Check.eq(
                dsa.sign(msg, keys.secretKey, Bytes.EMPTY, pinned),
                hedgedPin,
                "$at a pinned rnd is reproducible",
            )
            Check.ok(
                !hedgedPin.contentEquals(deterministic),
                "$at a different rnd gives a different signature",
            )

            val a = dsa.sign(msg, keys.secretKey)
            val b = dsa.sign(msg, keys.secretKey)
            Check.ok(!a.contentEquals(b), "$at the default is hedged, not deterministic")

            Check.ok(dsa.verify(deterministic, msg, keys.publicKey), "$at deterministic verifies")
            Check.ok(dsa.verify(a, msg, keys.publicKey), "$at hedged verifies")

            for (size in listOf(0, 31, 33)) {
                Check.throwsWith("extraEntropy", "$at extraEntropy of $size bytes") {
                    dsa.sign(msg, keys.secretKey, Bytes.EMPTY, ByteArray(size))
                }
            }
        }
    }

    /**
     * The order of the two guards at the top of `signInternal`, which is the half of the reference's
     * `ML-DSA prepares and cleans entropy before secret expansion` that needs no RNG seam.
     *
     * Given *both* a bad `rnd` and a bad secret key, the `rnd` error has to win. Not because the
     * message is nicer, but because the alternative means the key was already decoded and
     * NTT-expanded before anything was checked — 23 secret polynomials plus ρ, K, tr and µ live in the
     * heap on a path that then throws, with no `finally` to reach them. An implementation that
     * validated in the convenient order passes every vector in this repository and fails only here.
     */
    test("ML-DSA validates entropy before it expands the key") {
        val bad = ByteArray(31)
        for ((level, dsa) in Params.dsaLevels) {
            val at = "ML-DSA-$level"
            Check.throwsWith("extraEntropy", "$at empty secretKey and short extraEntropy") {
                dsa.signInternal(byteArrayOf(1), Bytes.EMPTY, bad)
            }
            // And with valid entropy the key error is still reported, not swallowed.
            Check.throwsWith("secretKey", "$at empty secretKey with valid extraEntropy") {
                dsa.signInternal(byteArrayOf(1), Bytes.EMPTY, ByteArray(32))
            }
        }
        // Same again for a key of the right length whose `s1` does not decode — the η = 2 levels only,
        // for the reason given under "ML-DSA rejects a malformed secret key".
        for ((level, dsa) in listOf("44" to Params.mlDsa44, "87" to Params.mlDsa87)) {
            val malformed = ByteArray(dsa.secretKeyLen)
            malformed[32 + 32 + 64] = 7
            Check.throwsWith("extraEntropy", "ML-DSA-$level malformed secretKey and short extraEntropy") {
                dsa.signInternal(byteArrayOf(1), malformed, bad)
            }
        }
    }

    /**
     * Fresh keys work without a caller-supplied seed, and two of them differ.
     *
     * This is the only case that exercises `Bytes.random` as the schemes' entropy source; every other
     * test in the file pins the seed so its result is reproducible.
     */
    test("keygen without a seed produces working keys") {
        for ((level, kem) in Params.kemLevels) {
            val a: MlKem.KeyPair = kem.keygen()
            val b = kem.keygen()
            Check.ok(!a.publicKey.contentEquals(b.publicKey), "ML-KEM-$level two keys differ")
            val sealed = kem.encapsulate(a.publicKey)
            Check.eq(kem.decapsulate(sealed.cipherText, a.secretKey), sealed.sharedSecret, "ML-KEM-$level round trip")
        }
        for ((level, dsa) in Params.dsaLevels) {
            val keys = dsa.keygen()
            val msg = Bytes.random(64)
            Check.ok(dsa.verify(dsa.sign(msg, keys.secretKey), msg, keys.publicKey), "ML-DSA-$level round trip")
        }
    }
}

private fun unchanged(value: ByteArray, snapshot: ByteArray, what: String) =
    Check.eq(value, snapshot, "$what was mutated")
