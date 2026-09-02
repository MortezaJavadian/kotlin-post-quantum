package io.github.mortezajavadian.pq.mlkem

import io.github.mortezajavadian.pq.core.Bytes
import io.github.mortezajavadian.pq.core.Sha3
import io.github.mortezajavadian.pq.lattice.BitPacker
import io.github.mortezajavadian.pq.lattice.Crystals
import io.github.mortezajavadian.pq.lattice.IntCoder

/**
 * ML-KEM's ring: `Z_3329[x]/(x^256 + 1)`.
 *
 * `f = 3303 = 128⁻¹ mod 3329` and one skipped NTT stage, both for the same reason — 3329 has no
 * 512th primitive root of unity, so the transform bottoms out at 128 degree-one polynomials instead
 * of 256 scalars. That is also why [MlKem.multiplyNtt] is a base-case multiply rather than a
 * pointwise product.
 */
internal object KyberRing : Crystals(
    n = 256,
    q = 3329,
    f = 3303,
    rootOfUnity = 17,
    brvBits = 7,
    skipStages = 1,
)

/**
 * FIPS-203 §4.2.1 `Compress_d` / `Decompress_d`, as an [IntCoder] so the bit packer can apply it
 * per coefficient.
 *
 * `encode` is `round(2^d · i / q) mod 2^d`. The rounding is the subtle part: written as
 * `((i << d) + q/2) / q` it is a *fractional* midpoint — `q/2` is 1664.5 — and the result is
 * truncated. Rendered in exact integers that is `(2·(i << d) + q) / (2q)` floored, which is what this
 * does. The two agree for every input because `2·(i << d) + q` is odd while `2q` is even, so the
 * quotient never sits on an integer boundary where the rounding direction could differ.
 *
 * The `mod 2^d` is left to the packer's mask, where it belongs: the top coefficient genuinely wraps
 * to zero and the wrap is part of the format.
 *
 * `decode` is `round(q · i / 2^d)`, exact integer arithmetic already. For `d >= 12` there is nothing
 * to compress and [ByteCoder12] is used instead of this class.
 */
private class Compress(private val d: Int) : IntCoder {
    private val half = 1 shl (d - 1)

    override fun encode(value: Int): Int {
        val q = KyberRing.q.toLong()
        return ((2L * (value.toLong() shl d) + q) / (2L * q)).toInt()
    }

    override fun decode(value: Int): Int = (value * KyberRing.q + half) ushr d
}

/**
 * FIPS-203 §4.2.1 `ByteEncode_12` / `ByteDecode_12` — the raw 12-bit field, not compression.
 *
 * `decode` is where the whole of §7.2's modulus check lives, and it is one line: `Algorithm 6`
 * takes the packed word `mod m` with `m = q` when `d = 12` (`m = 2^d` only for `d < 12`), so a
 * 12-bit word at or above `q` is *not* a coefficient and does not survive the reduction. Since a
 * masked 12-bit word is at most 4095 and `4095 − 3329 = 766 < q`, one conditional subtraction is
 * that reduction exactly.
 *
 * Dropping it would be invisible in every valid operation — an honest key's coefficients are already
 * in `[0, q)` — and would silently turn §7.2's `ByteEncode_12(ByteDecode_12(ek)) == ek` test into a
 * tautology, since re-encoding twelve unreduced bits returns them unchanged. A malformed
 * encapsulation key would then be accepted, which is both a standards deviation and, because these
 * keys arrive from the wire, protocol-visible. It is checked directly by
 * `ML-KEM accepts q−1 and rejects q` in the basic suite and by ACVP's `encapsulationKeyCheck`
 * vectors.
 */
private object ByteCoder12 : IntCoder {
    override fun encode(value: Int): Int = value

    override fun decode(value: Int): Int = if (value >= KyberRing.q) value - KyberRing.q else value
}

/** [Compress] for `d < 12`, [ByteCoder12] above — `Compress_12` is the identity, `ByteDecode_12` is not. */
private fun compressCoder(d: Int): IntCoder = if (d >= 12) ByteCoder12 else Compress(d)

/**
 * ML-KEM (FIPS-203, a.k.a. CRYSTALS-Kyber): key encapsulation, plus the raw K-PKE layer underneath
 * it.
 *
 * Three things about this scheme shape everything below and are worth stating once:
 *
 *  1. **Decapsulation never fails.** Given a ciphertext produced under a different public key it
 *     returns a *different* shared secret rather than an error — the implicit reject of §7.3, where
 *     the re-encryption mismatch silently swaps in `SHAKE256(z || ct)`. Callers therefore cannot use
 *     an exception to detect the wrong key, and the app does not: it compares the derived secret's
 *     effect instead.
 *  2. **K-PKE is exposed.** [kpkeEncrypt] is the bare public-key encryption FIPS-203 builds the KEM
 *     out of and explicitly declines to standardise for direct use. It is reachable here because the
 *     CA login exchange encrypts a fixed 32-byte payload under the CA's public key with a
 *     caller-supplied seed — a deterministic operation the KEM interface cannot express.
 *  3. **Both key halves are polynomials, and the transform is not pointwise.** See [KyberRing]:
 *     3329 admits only a 256th root of unity, so NTT-domain multiplication is [multiplyNtt]'s
 *     degree-one base case, not a coefficient product.
 *
 * Instances are immutable after construction; every method allocates its own working polynomials, so
 * one shared instance per parameter set is safe on any thread.
 *
 * The three standardised sets ship as [mlKem512], [mlKem768] and [mlKem1024] — prefer them. The
 * constructor is public because FIPS-203 Table 2's five parameters map onto it one-for-one with
 * nothing derived, so a set from a draft or a research variant is expressible; it is also unvalidated,
 * and a plausible-looking typo (`dv = 5` where the set says 4) yields a self-consistent scheme that
 * simply is not ML-KEM and interoperates with nothing.
 */
public class MlKem(
    private val k: Int,
    private val eta1: Int,
    private val eta2: Int,
    du: Int,
    dv: Int,
) {

    private val n = KyberRing.n
    private val q = KyberRing.q

    /** The 1-bit message polynomial: 32 bytes ⇄ 256 coefficients of 0 or ⌈q/2⌉. */
    private val poly1 = BitPacker(1, compressCoder(1), n)

    /** The uncompressed 12-bit field, used by both key halves. */
    private val poly12 = BitPacker(12, compressCoder(12), n)

    private val polyU = BitPacker(du, compressCoder(du), n)
    private val polyV = BitPacker(dv, compressCoder(dv), n)

    /** `384k + 32` — the encoded `t̂` vector followed by the matrix seed ρ. */
    public val publicKeyLen: Int = k * poly12.bytesLen + 32

    /** `384k` — K-PKE's secret key is just the encoded `ŝ`. */
    public val kpkeSecretKeyLen: Int = k * poly12.bytesLen

    /** `32(du·k + dv)`. */
    public val cipherTextLen: Int = k * polyU.bytesLen + polyV.bytesLen

    /** `768k + 96` — `dkPKE || ek || H(ek) || z`. */
    public val secretKeyLen: Int = kpkeSecretKeyLen + publicKeyLen + 32 + 32

    /**
     * Encapsulation output. [sharedSecret] is 32 bytes; [cipherText] is [cipherTextLen].
     *
     * Holds the arrays, does not copy them. [sharedSecret] is key material: pass it to a KDF and then
     * `Bytes.clean` it. Not a `data class` on purpose — a generated `equals` would compare byte arrays
     * by identity and read as a content comparison.
     */
    public class Encapsulated(public val cipherText: ByteArray, public val sharedSecret: ByteArray)

    /**
     * A keypair, in the encodings the wire and the key store use.
     *
     * Holds the arrays, does not copy them; [secretKey] is live key material until you wipe it. Not a
     * `data class`, for the reason in [Encapsulated].
     */
    public class KeyPair(public val publicKey: ByteArray, public val secretKey: ByteArray)

    // -------------------------------------------------------------------------------------------
    // Ring operations
    // -------------------------------------------------------------------------------------------

    private fun polyAdd(a: IntArray, b: IntArray) {
        for (i in 0 until n) a[i] = KyberRing.mod(a[i] + b[i])
    }

    private fun polySub(a: IntArray, b: IntArray) {
        for (i in 0 until n) a[i] = KyberRing.mod(a[i] - b[i])
    }

    /**
     * FIPS-203 §4.3.1 `MultiplyNTTs`, **in place on [f]**.
     *
     * Because the transform stops one stage early (see [KyberRing]) the NTT domain holds 128
     * degree-one polynomials rather than 256 scalars, so each pair of coefficients is multiplied
     * modulo `x² − ζ^(2·brv(i)+1)` — the `BaseCaseMultiply` of §4.3.1. The ζ index is
     * `zetas[64 + i/2]`, negated on odd `i`, which is exactly the pairing the skipped stage leaves
     * behind.
     *
     * Mutating [f] is not an optimisation detail that can be undone: callers rely on it. `t̂ᵢ` in
     * [kpkeEncrypt] and `ŝᵢ` in [kpkeDecrypt] are both consumed by being multiplied, and the
     * accumulate loops read the returned array as the addend.
     *
     * Products reach `q³ ≈ 3.7·10¹⁰`, past 32 bits, so the arithmetic is 64-bit. That is also why
     * there is no Montgomery form here: a plain `%` on a `Long` is exact and needs no conditioning.
     */
    private fun multiplyNtt(f: IntArray, g: IntArray): IntArray {
        val zetas = KyberRing.zetas
        for (i in 0 until n / 2) {
            var z = zetas[64 + (i shr 1)]
            if (i and 1 == 1) z = -z
            val a0 = f[2 * i].toLong()
            val a1 = f[2 * i + 1].toLong()
            val b0 = g[2 * i].toLong()
            val b1 = g[2 * i + 1].toLong()
            f[2 * i] = KyberRing.mod(a1 * b1 * z + a0 * b0)
            f[2 * i + 1] = KyberRing.mod(a0 * b1 + a1 * b0)
        }
        return f
    }

    // -------------------------------------------------------------------------------------------
    // Sampling
    // -------------------------------------------------------------------------------------------

    /**
     * FIPS-203 §4.2.2 `SampleNTT` — one matrix entry, uniform over `Z_q`, straight into the NTT
     * domain.
     *
     * Rejection sampling on 12-bit fields: each 3-byte group yields two candidates and each is kept
     * only if it is below `q`. The loop therefore consumes an unbounded number of XOF blocks and
     * cannot be given a fixed budget — the expected count is just over one 168-byte block, but the
     * tail is unbounded, which is why [Sha3.SeededXof] streams.
     *
     * The `% 3 != 0` guard is not paranoia: SHAKE-128's 168-byte rate is divisible by 3 precisely so
     * that a 3-byte group never straddles two blocks. A different block length would silently drop
     * or duplicate bits at every boundary.
     */
    private fun sampleNtt(xof: Sha3.SeededXof): IntArray {
        val r = IntArray(n)
        var j = 0
        while (j < n) {
            val b = xof.next()
            if (b.size % 3 != 0) throw IllegalStateException("SampleNTT: unaligned block")
            var i = 0
            while (j < n && i + 3 <= b.size) {
                val b0 = b[i].toInt() and 0xFF
                val b1 = b[i + 1].toInt() and 0xFF
                val b2 = b[i + 2].toInt() and 0xFF
                val d1 = (b0 or (b1 shl 8)) and 0xFFF
                val d2 = ((b1 ushr 4) or (b2 shl 4)) and 0xFFF
                if (d1 < q) r[j++] = d1
                if (j < n && d2 < q) r[j++] = d2
                i += 3
            }
        }
        return r
    }

    /**
     * FIPS-203 §4.2.2 `SamplePolyCBD_η` — the centred binomial noise.
     *
     * `PRF(η·64, seed, nonce)` is consumed as a bit stream: each coefficient is the difference of the
     * Hamming weights of two consecutive η-bit runs, reduced mod `q` so that −η becomes `q − η`.
     * Reading it bit-by-bit rather than through a 32-bit word view keeps the traversal order
     * unambiguous — LSB-first within each byte, bytes in order — which is the order the spec's
     * `BytesToBits` defines and the only one that matches.
     */
    private fun sampleCbd(seed: ByteArray, nonce: Int, eta: Int): IntArray {
        val buf = Sha3.prf(eta * n / 4, seed, nonce)
        val r = IntArray(n)
        var p = 0
        var acc = 0
        var len = 0
        var first = 0
        for (byte in buf) {
            val value = byte.toInt() and 0xFF
            for (bit in 0 until 8) {
                acc += (value ushr bit) and 1
                len++
                if (len == eta) {
                    first = acc
                    acc = 0
                } else if (len == 2 * eta) {
                    r[p++] = KyberRing.mod(first - acc)
                    acc = 0
                    len = 0
                }
            }
        }
        Bytes.clean(buf)
        return r
    }

    // -------------------------------------------------------------------------------------------
    // K-PKE (FIPS-203 §5) — the public-key encryption the KEM is built from
    // -------------------------------------------------------------------------------------------

    /**
     * `K-PKE.KeyGen`, from a 32-byte seed.
     *
     * `(ρ, σ) ← G(seed || k)`; ρ expands the matrix `A`, σ seeds the secret and error noise. The
     * trailing `k` byte is FIPS-203's domain separation between parameter sets — without it the same
     * seed would give related keys at 512, 768 and 1024.
     *
     * `t̂ ← Â ∘ ŝ + ê`, with the matrix sampled **transposed** relative to [kpkeEncrypt]: here entry
     * `(j, i)`, there `(i, j)`. That asymmetry is the spec's and is what makes `t̂` and the
     * ciphertext's `u` agree; swapping it produces a self-consistent keypair that no correct peer can
     * talk to.
     *
     * `seed` must come from a CSPRNG and must never be reused: it *is* the private key, and anyone
     * holding it reproduces this keypair exactly. The array is the caller's — wipe it.
     */
    public fun kpkeKeygen(seed: ByteArray): KeyPair {
        Bytes.requireSize(seed, 32, "seed")
        val seedDst = ByteArray(33)
        seed.copyInto(seedDst)
        seedDst[32] = k.toByte()
        val seedHash = Sha3.hash512(seedDst)
        val rho = seedHash.copyOfRange(0, 32)
        val sigma = seedHash.copyOfRange(32, 64)

        val sHat = Array(k) { KyberRing.nttEncode(sampleCbd(sigma, it, eta1)) }
        val tHat = arrayOfNulls<IntArray>(k)
        val xof = Sha3.xof128(rho)
        for (i in 0 until k) {
            val e = KyberRing.nttEncode(sampleCbd(sigma, k + i, eta1))
            for (j in 0 until k) {
                val aji = sampleNtt(xof.seek(j, i))
                polyAdd(e, multiplyNtt(aji, sHat[j]))
            }
            tHat[i] = e
        }
        xof.clean()

        @Suppress("UNCHECKED_CAST")
        val t = tHat as Array<IntArray>
        val publicKey = ByteArray(publicKeyLen)
        poly12.encodeVecInto(t, publicKey, 0, k)
        rho.copyInto(publicKey, k * poly12.bytesLen)
        val secretKey = ByteArray(kpkeSecretKeyLen)
        poly12.encodeVecInto(sHat, secretKey, 0, k)

        Bytes.clean(rho, sigma, seedDst, seedHash)
        Bytes.cleanPolys(*sHat)
        Bytes.cleanPolys(*t)
        return KeyPair(publicKey, secretKey)
    }

    /**
     * `K-PKE.Encrypt` — encrypts a 32-byte message under [publicKey] with caller-supplied randomness.
     *
     * Deterministic in [seed]: the same triple always yields the same ciphertext. That is what the CA
     * login exchange needs and what the KEM interface cannot offer, since [encapsulate] derives its
     * own randomness from the message.
     *
     * `u ← NTT⁻¹(Âᵀ ∘ r̂) + e₁`, `v ← NTT⁻¹(t̂ᵀ ∘ r̂) + e₂ + Decompress₁(m)`, then both are lossily
     * compressed to `du` and `dv` bits. The compression is why decryption is only *approximately*
     * inverse and why the KEM re-encrypts to check.
     *
     * The determinism cuts both ways: [seed] is the encryption's only entropy, so it must be 32 fresh
     * CSPRNG bytes per `(publicKey, msg)` unless reproducibility is the point. Encrypting two different
     * messages under one key with the same seed publishes their difference — the noise cancels and
     * `v₁ - v₂` decompresses to `m₁ ⊕ m₂`.
     */
    public fun kpkeEncrypt(publicKey: ByteArray, msg: ByteArray, seed: ByteArray): ByteArray {
        Bytes.requireSize(publicKey, publicKeyLen, "publicKey")
        Bytes.requireSize(msg, 32, "message")
        // FIPS-203 Algorithm 14 fixes `r ∈ B³²`, and SHAKE would absorb any width without complaint,
        // so this is the one input whose misuse is otherwise silent: a short or empty seed still
        // produces a well-formed ciphertext, and one an attacker holding `ek` can reproduce — which
        // recovers the plaintext. The reference never has to state the width because it does not
        // expose this function; here it is reachable, so it is checked.
        Bytes.requireSize(seed, 32, "seed")
        val tHat = poly12.decodeVec(publicKey, 0, k)
        val rho = publicKey.copyOfRange(k * poly12.bytesLen, publicKeyLen)

        val rHat = Array(k) { KyberRing.nttEncode(sampleCbd(seed, it, eta1)) }
        val xof = Sha3.xof128(rho)
        val acc = IntArray(n)
        val u = arrayOfNulls<IntArray>(k)
        for (i in 0 until k) {
            val e1 = sampleCbd(seed, k + i, eta2)
            val tmp = IntArray(n)
            for (j in 0 until k) {
                val aij = sampleNtt(xof.seek(i, j))
                polyAdd(tmp, multiplyNtt(aij, rHat[j]))
            }
            polyAdd(e1, KyberRing.nttDecode(tmp))
            u[i] = e1
            polyAdd(acc, multiplyNtt(tHat[i], rHat[i]))
            tmp.fill(0)
        }
        xof.clean()

        val e2 = sampleCbd(seed, 2 * k, eta2)
        polyAdd(e2, KyberRing.nttDecode(acc))
        val v = poly1.decode(msg, 0)
        polyAdd(v, e2)

        val cipherText = ByteArray(cipherTextLen)
        @Suppress("UNCHECKED_CAST")
        polyU.encodeVecInto(u as Array<IntArray>, cipherText, 0, k)
        polyV.encodeInto(v, cipherText, k * polyU.bytesLen)

        Bytes.cleanPolys(*tHat)
        Bytes.cleanPolys(*rHat)
        Bytes.cleanPolys(*u)
        Bytes.cleanPolys(acc, e2, v)
        Bytes.clean(rho)
        return cipherText
    }

    /**
     * `K-PKE.Decrypt` — recovers the 32-byte message.
     *
     * `m ← Compress₁(v − NTT⁻¹(ŝᵀ ∘ û))`. The 1-bit compression is what absorbs the noise the
     * ciphertext's `du`/`dv` truncation left behind: each coefficient is rounded to whichever of `0`
     * or `⌈q/2⌉` it is nearer, so a small perturbation cannot change the recovered bit.
     *
     * K-PKE is IND-CPA only, and this is where that bites: a tampered ciphertext decrypts to a
     * different message instead of failing, so exposing it to an attacker who learns anything about the
     * result turns it into a chosen-ciphertext oracle. [decapsulate] is the CCA-secure wrapper.
     */
    public fun kpkeDecrypt(cipherText: ByteArray, secretKey: ByteArray): ByteArray {
        Bytes.requireSize(cipherText, cipherTextLen, "cipherText")
        // Two widths are legal because two callers are: a K-PKE caller passes `dkPKE` alone, while
        // [decapsulate] passes the whole ML-KEM secret key and this reads its leading `384k` bytes.
        // Anything else would otherwise reach the bit packer and surface as an index-out-of-bounds
        // from inside a coder — and a *longer* ciphertext would be accepted with its tail ignored,
        // which makes the encoding non-canonical for anyone comparing or deduplicating by bytes.
        Bytes.require(secretKey.size == kpkeSecretKeyLen || secretKey.size == secretKeyLen) {
            "secretKey: expected $kpkeSecretKeyLen or $secretKeyLen bytes, got ${secretKey.size}"
        }
        val u = polyU.decodeVec(cipherText, 0, k)
        val v = polyV.decode(cipherText, k * polyU.bytesLen)
        val sHat = poly12.decodeVec(secretKey, 0, k)
        val acc = IntArray(n)
        for (i in 0 until k) {
            polyAdd(acc, multiplyNtt(sHat[i], KyberRing.nttEncode(u[i])))
        }
        polySub(v, KyberRing.nttDecode(acc))
        val msg = poly1.encode(v)
        Bytes.cleanPolys(*sHat)
        Bytes.cleanPolys(*u)
        Bytes.cleanPolys(acc, v)
        return msg
    }

    // -------------------------------------------------------------------------------------------
    // ML-KEM (FIPS-203 §7)
    // -------------------------------------------------------------------------------------------

    /**
     * `ML-KEM.KeyGen`, from a 64-byte seed — 32 bytes for K-PKE, 32 for the implicit-reject value `z`.
     *
     * The secret key is the concatenation `dkPKE || ek || H(ek) || z`: the KEM has to re-encrypt
     * during decapsulation, so it carries the public key and its hash inside the private one. That is
     * why [secretKeyLen] is `768k + 96` and not `384k`.
     *
     * The seed belongs to the caller and is left untouched; the 32-byte K-PKE half this copies out of
     * it is wiped before returning.
     *
     * Deterministic, so the seed carries the whole keypair's secrecy: 64 CSPRNG bytes, never reused,
     * wiped once it has been used. Use [keygen] with no argument unless you are deriving a key from
     * something you already store.
     */
    public fun keygen(seed: ByteArray): KeyPair {
        Bytes.requireSize(seed, 64, "seed")
        val kpkeSeed = seed.copyOfRange(0, 32)
        val inner = kpkeKeygen(kpkeSeed)
        Bytes.clean(kpkeSeed)
        val publicKeyHash = Sha3.hash256(inner.publicKey)
        val secretKey = ByteArray(secretKeyLen)
        var pos = 0
        inner.secretKey.copyInto(secretKey, pos)
        pos += inner.secretKey.size
        inner.publicKey.copyInto(secretKey, pos)
        pos += inner.publicKey.size
        publicKeyHash.copyInto(secretKey, pos)
        pos += 32
        seed.copyInto(secretKey, pos, 32, 64)
        Bytes.clean(inner.secretKey, publicKeyHash)
        return KeyPair(inner.publicKey, secretKey)
    }

    /**
     * As [keygen], with a freshly generated seed.
     *
     * Separate from the seeded overload rather than a default argument so the generated seed can be
     * wiped once the key is built — a default expression would leave it live in the caller's frame.
     */
    public fun keygen(): KeyPair {
        val seed = Bytes.random(64)
        try {
            return keygen(seed)
        } finally {
            Bytes.clean(seed)
        }
    }

    /**
     * `ML-KEM.Encaps` — a fresh shared secret plus the ciphertext that carries it.
     *
     * `(K, r) ← G(m || H(ek))` derives both the secret and the encryption randomness from the
     * message, so the ciphertext is a deterministic function of `(ek, m)` and the peer can re-derive
     * it during decapsulation.
     *
     * The modulus round-trip before it is FIPS-203 §7.2's input check, and it is a real check rather
     * than a formality: [ByteCoder12]'s decode reduces each 12-bit word mod `q`, so a word in
     * `[q, 4095]` re-encodes to something else and the comparison fails. It would also catch a
     * truncated or padded public key.
     *
     * Internal on purpose. [msg] is the 32 bytes of *randomness* `m` — it is not a payload, and it
     * determines the shared secret outright — but nothing about `encapsulate(publicKey, msg)` says so,
     * and `encapsulate(pk, "a 32-byte string".toByteArray())` round-trips perfectly while handing the
     * session key to anyone who guesses the string. The one-argument [encapsulate] is the KEM. For real
     * encryption use [kpkeEncrypt], which takes a message *and* separate coins; for a reproducible
     * keypair use [keygen] with a seed; ACVP's specified-`m` vectors reach this from the test module.
     */
    internal fun encapsulate(publicKey: ByteArray, msg: ByteArray): Encapsulated {
        Bytes.requireSize(publicKey, publicKeyLen, "publicKey")
        Bytes.requireSize(msg, 32, "message")
        val encodedLen = k * poly12.bytesLen
        val roundTrip = ByteArray(encodedLen)
        val decoded = poly12.decodeVec(publicKey, 0, k)
        poly12.encodeVecInto(decoded, roundTrip, 0, k)
        Bytes.cleanPolys(*decoded)
        if (!Bytes.equal(roundTrip, publicKey, 0, encodedLen)) {
            Bytes.clean(roundTrip)
            throw IllegalArgumentException("ML-KEM.encapsulate: wrong publicKey modulus")
        }
        Bytes.clean(roundTrip)

        val publicKeyHash = Sha3.hash256(publicKey)
        val kr = Sha3.hash512(msg, publicKeyHash)
        val encryptionSeed = kr.copyOfRange(32, 64)
        val cipherText = kpkeEncrypt(publicKey, msg, encryptionSeed)
        val sharedSecret = kr.copyOfRange(0, 32)
        Bytes.clean(kr, encryptionSeed, publicKeyHash)
        return Encapsulated(cipherText, sharedSecret)
    }

    /**
     * `ML-KEM.Encaps` against [publicKey], with the message generated internally.
     *
     * This is the KEM: it draws 32 CSPRNG bytes, derives the shared secret and the encryption
     * randomness from them, wipes them, and hands back the secret and the ciphertext. Nothing about the
     * randomness is a parameter, which is the point — see the internal overload for why. Applies
     * FIPS-203 §7.2's modulus check to [publicKey] and throws if it fails.
     *
     * The returned [Encapsulated.sharedSecret] is live key material.
     */
    public fun encapsulate(publicKey: ByteArray): Encapsulated {
        val msg = Bytes.random(32)
        try {
            return encapsulate(publicKey, msg)
        } finally {
            Bytes.clean(msg)
        }
    }

    /**
     * `ML-KEM.Decaps` — recovers the shared secret, or something that is not it.
     *
     * The re-encryption comparison is the whole security argument of the Fujisaki–Okamoto transform
     * and the reason this returns a value in every case: on mismatch it yields `J(z || c)` instead of
     * `K̂`, which is indistinguishable from a real secret to anyone who does not hold `z`. A caller
     * cannot learn "wrong key" from this function — only that the session which used the secret did
     * not work.
     *
     * Both candidates are computed unconditionally and the loser is wiped, so which branch was taken
     * is not visible in allocation or timing.
     *
     * It does throw on one input: a [secretKey] whose embedded `H(ek)` does not match the public key it
     * carries, which is §7.3's check and a malformed key rather than a wrong one.
     */
    public fun decapsulate(cipherText: ByteArray, secretKey: ByteArray): ByteArray {
        Bytes.requireSize(secretKey, secretKeyLen, "secretKey")
        Bytes.requireSize(cipherText, cipherTextLen, "cipherText")
        val encodedLen = k * poly12.bytesLen
        val hashStart = encodedLen + publicKeyLen
        val publicKey = secretKey.copyOfRange(encodedLen, hashStart)
        val test = Sha3.hash256(publicKey)
        val hashOk = Bytes.equal(test, secretKey, hashStart, hashStart + 32)
        Bytes.clean(test)
        if (!hashOk) {
            Bytes.clean(publicKey)
            throw IllegalArgumentException("invalid secretKey: hash check failed")
        }
        val publicKeyHash = secretKey.copyOfRange(hashStart, hashStart + 32)
        val z = secretKey.copyOfRange(hashStart + 32, secretKeyLen)

        val msg = kpkeDecrypt(cipherText, secretKey)
        val kr = Sha3.hash512(msg, publicKeyHash)
        val kHat = kr.copyOfRange(0, 32)
        val encryptionSeed = kr.copyOfRange(32, 64)
        val cipherText2 = kpkeEncrypt(publicKey, msg, encryptionSeed)
        val valid = Bytes.equal(cipherText, cipherText2)
        val kBar = Sha3.shake256(32).update(z).update(cipherText).digest()
        Bytes.clean(msg, cipherText2, kr, encryptionSeed, z, publicKey, publicKeyHash)
        Bytes.clean(if (valid) kBar else kHat)
        return if (valid) kHat else kBar
    }
}

/**
 * ML-KEM-512 — FIPS-203 Table 2, category-1 security. `k = 2`.
 *
 * The three sets differ only in these five numbers, and the numbers are not interchangeable: the
 * `seed || k` domain separation in [MlKem.kpkeKeygen] means one seed gives three unrelated keypairs, so
 * a peer on a different set does not interoperate — it fails on a length check, not silently.
 */
public val mlKem512: MlKem = MlKem(k = 2, eta1 = 3, eta2 = 2, du = 10, dv = 4)

/** ML-KEM-768 — FIPS-203 Table 2, category-3 security. `k = 3`. The usual default. */
public val mlKem768: MlKem = MlKem(k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4)

/** ML-KEM-1024 — FIPS-203 Table 2, category-5 security. `k = 4`. */
public val mlKem1024: MlKem = MlKem(k = 4, eta1 = 2, eta2 = 2, du = 11, dv = 5)

