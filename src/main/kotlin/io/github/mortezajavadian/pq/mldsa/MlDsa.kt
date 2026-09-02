package io.github.mortezajavadian.pq.mldsa

import io.github.mortezajavadian.pq.core.Bytes
import io.github.mortezajavadian.pq.core.Sha3
import io.github.mortezajavadian.pq.lattice.BitPacker
import io.github.mortezajavadian.pq.lattice.IdentityCoder

/**
 * ML-DSA (FIPS-204, a.k.a. CRYSTALS-Dilithium): key generation, signing and verification.
 *
 * The scheme is Fiat–Shamir with aborts. A signature is a proof of knowledge of the short secret
 * `(s1, s2)` satisfying `t = A·s1 + s2`, and "with aborts" is not a footnote: [sign] samples a masking
 * vector, checks four norm bounds on what comes out, and *restarts from a fresh mask* if any of them
 * fails. So signing is a loop with a data-dependent number of iterations, and the loop counter κ is
 * itself an input to the mask expansion — which is why a signature is reproducible only if the
 * per-signature randomness is pinned.
 *
 * Three details below are protocol-visible and easy to get subtly wrong:
 *
 *  1. **The public API signs an envelope, not the message.** [sign] and [verify] prepend
 *     `0x00 || len(ctx) || ctx` — two bytes for the empty context every caller here uses. The
 *     `internal` variants in FIPS-204 do not. Signing the bare message produces a signature that
 *     verifies nowhere.
 *  2. **`MakeHint` follows the reference implementation, not the standard's text.** The two disagree;
 *     see [makeHint]. Following FIPS-204 literally produces signatures that fail the official test
 *     vectors, so the reference form is the interoperable one.
 *  3. **Signing is randomised by default.** Two signatures over the same message under the same key
 *     differ, and both verify. Determinism is opt-in.
 *
 * Instances are immutable; every method allocates its own working polynomials, so one shared instance
 * per parameter set is safe on any thread.
 *
 * Use [mlDsa44], [mlDsa65] or [mlDsa87]. The constructor is internal, unlike ML-KEM's: four of these
 * ten numbers are not free — `crhBytes` and `trBytes` are 64 in every standardised set, `cTildeBytes`
 * is `2λ/8`, and `gamma2` must be one of the two `(q−1)/88` and `(q−1)/32` values that live in
 * [DilithiumRing] and cannot be named from outside this module — while the rest silently select a
 * *different scheme* rather than a misconfigured one. FIPS-204 Table 1 has exactly three rows and all
 * three ship above.
 */
public class MlDsa internal constructor(
    private val k: Int,
    private val l: Int,
    private val gamma1: Int,
    private val gamma2: Int,
    private val tau: Int,
    private val eta: Int,
    private val omega: Int,
    private val cTildeBytes: Int,
    private val crhBytes: Int,
    private val trBytes: Int,
) {

    private val n = DilithiumRing.n
    private val q = DilithiumRing.q

    /** `τ·η` — the norm slack every rejection bound is measured against. */
    private val beta: Int = tau * eta

    // -------------------------------------------------------------------------------------------
    // Field coders and lengths
    // -------------------------------------------------------------------------------------------

    private val etaPacker = BitPacker(if (eta == 2) 3 else 4, EtaCoder(eta), n)
    private val t0Packer = BitPacker(DSA_D, T0Coder, n)
    private val t1Packer = BitPacker(10, IdentityCoder, n)
    private val zPacker = BitPacker(if (gamma1 == 1 shl 17) 18 else 20, ZCoder(gamma1), n)
    private val w1Packer = BitPacker(if (gamma2 == GAMMA2_1) 6 else 4, IdentityCoder, n)

    /** `32 + 320k` — ρ followed by the packed `t1` vector; 2592 bytes at ML-DSA-87. */
    public val publicKeyLen: Int = 32 + k * t1Packer.bytesLen

    /** `ρ || K || tr || s1 || s2 || t0`; 4896 bytes at ML-DSA-87. */
    public val secretKeyLen: Int =
        32 + 32 + trBytes + l * etaPacker.bytesLen + k * etaPacker.bytesLen + k * t0Packer.bytesLen

    /** `c̃ || z || h`; 4627 bytes at ML-DSA-87. Fixed, not variable. */
    public val signatureLen: Int = cTildeBytes + l * zPacker.bytesLen + omega + k

    /** Seed accepted by [keygen], and the per-signature randomness length. */
    public val seedLen: Int = 32

    private val zVecLen = l * zPacker.bytesLen
    private val w1VecLen = k * w1Packer.bytesLen

    /**
     * A keypair, in the FIPS-204 encodings.
     *
     * Holds the arrays, does not copy them; [secretKey] is live key material until you wipe it. Not a
     * `data class` — a generated `equals` would compare byte arrays by identity while reading as a
     * content comparison.
     */
    public class KeyPair(public val publicKey: ByteArray, public val secretKey: ByteArray)

    // -------------------------------------------------------------------------------------------
    // Ring operations
    // -------------------------------------------------------------------------------------------

    private fun polyAdd(a: IntArray, b: IntArray): IntArray {
        for (i in 0 until n) a[i] = DilithiumRing.mod(a[i] + b[i])
        return a
    }

    private fun polySub(a: IntArray, b: IntArray): IntArray {
        for (i in 0 until n) a[i] = DilithiumRing.mod(a[i] - b[i])
        return a
    }

    /** `t1 · 2^d`, left in place. Deliberately *not* reduced — [verify] feeds the result to the NTT. */
    private fun polyShiftl(p: IntArray): IntArray {
        for (i in 0 until n) p[i] = p[i] shl DSA_D
        return p
    }

    /**
     * `‖p‖∞ ≥ bound`, on the **signed** representative — true means "reject".
     *
     * The infinity norm of a ring element is defined on `smod`, so a coefficient of `q − 1` has norm
     * 1, not `q − 1`. Measuring the unsigned residue instead would reject essentially every valid
     * mask and make signing loop forever.
     */
    private fun polyChknorm(p: IntArray, bound: Int): Boolean {
        for (i in 0 until n) {
            val v = DilithiumRing.smod(p[i])
            if ((if (v < 0) -v else v) >= bound) return true
        }
        return false
    }

    /**
     * Pointwise product into a fresh polynomial.
     *
     * Pointwise is correct here and would not be for ML-KEM: `q` has a 512th root of unity, so the
     * transform reaches single coefficients. Products are 46-bit, hence the `Long`.
     */
    private fun multiplyNtt(a: IntArray, b: IntArray): IntArray {
        val c = IntArray(n)
        for (i in 0 until n) c[i] = DilithiumRing.mod(a[i].toLong() * b[i].toLong())
        return c
    }

    /** As [multiplyNtt] but accumulating into [dst], which saves one allocation per matrix entry. */
    private fun multiplyNttInto(dst: IntArray, a: IntArray, b: IntArray) {
        for (i in 0 until n) {
            dst[i] = DilithiumRing.mod(dst[i] + DilithiumRing.mod(a[i].toLong() * b[i].toLong()))
        }
    }

    // -------------------------------------------------------------------------------------------
    // Rounding and hints (FIPS-204 §7.4)
    // -------------------------------------------------------------------------------------------

    /** `HighBits(r)` — `r1` of the `(r1, r0)` split with `r ≡ r1·2γ₂ + r0`. */
    private fun highBits(r: Int): Int {
        val rPlus = DilithiumRing.mod(r)
        val r0 = DilithiumRing.smod(rPlus, 2 * gamma2)
        // The one boundary case: r ≡ −1 has no representative with r1 in range, so it folds to 0.
        if (rPlus - r0 == q - 1) return 0
        return (rPlus - r0) / (2 * gamma2)
    }

    /** `LowBits(r)` — `r0`, signed, in `(−γ₂, γ₂]`. */
    private fun lowBits(r: Int): Int {
        val rPlus = DilithiumRing.mod(r)
        val r0 = DilithiumRing.smod(rPlus, 2 * gamma2)
        if (rPlus - r0 == q - 1) return r0 - 1
        return r0
    }

    /**
     * `MakeHint` — one bit saying whether adding `z` to `r` would carry into the high bits.
     *
     * **This is the dilithium reference implementation's condition, not FIPS-204's.** The standard
     * defines it as `HighBits(r + z) ≠ HighBits(r)`; the reference tests `z` against γ₂ directly. The
     * two disagree on boundary inputs even though both agree on `Decompose`, and the official test
     * vectors follow the reference — so the standard's form, implemented literally, produces
     * signatures that verify against neither the vectors nor any deployed peer. The reference form is
     * therefore the interoperable one and is what is used here.
     *
     * See https://github.com/GiacomoPope/dilithium-py#optimising-decomposition-and-making-hints
     */
    private fun makeHint(z: Int, r: Int): Int =
        if (z <= gamma2 || z > q - gamma2 || (z == q - gamma2 && r == 0)) 0 else 1

    /** `UseHint` — the verifier's reconstruction of `HighBits`, nudged by the hint bit. */
    private fun useHint(h: Int, r: Int): Int {
        val m = (q - 1) / (2 * gamma2)
        val rPlus = DilithiumRing.mod(r)
        val r0raw = DilithiumRing.smod(rPlus, 2 * gamma2)
        val boundary = rPlus - r0raw == q - 1
        val r1 = if (boundary) 0 else (rPlus - r0raw) / (2 * gamma2)
        val r0 = if (boundary) r0raw - 1 else r0raw
        if (h == 1) return if (r0 > 0) DilithiumRing.mod(r1 + 1, m) else DilithiumRing.mod(r1 - 1, m)
        return r1
    }

    /** `Power2Round(r)` — the `t = t1·2^d + t0` split, `t0` signed. */
    private fun power2RoundHigh(r: Int): Int {
        val rPlus = DilithiumRing.mod(r)
        return (rPlus - DilithiumRing.smod(rPlus, 1 shl DSA_D)) shr DSA_D
    }

    private fun power2RoundLow(r: Int): Int =
        DilithiumRing.smod(DilithiumRing.mod(r), 1 shl DSA_D)

    // -------------------------------------------------------------------------------------------
    // The hint encoding (FIPS-204 §7.2 `HintBitPack`)
    // -------------------------------------------------------------------------------------------

    /**
     * Packs the hint vector as `ω` coefficient indices followed by `k` running totals.
     *
     * Not a bit-field like every other structure here: the hint is sparse — at most ω of the `256k`
     * bits are set — so it is stored as the *positions* of the set bits, ascending within each
     * polynomial, with `res[ω + i]` holding the count after polynomial `i`. Positions past the last
     * one are left zero.
     */
    private fun encodeHint(h: Array<IntArray>, dst: ByteArray, offset: Int) {
        var pos = 0
        for (i in 0 until k) {
            for (j in 0 until n) if (h[i][j] != 0) dst[offset + pos++] = j.toByte()
            dst[offset + omega + i] = pos.toByte()
        }
    }

    /**
     * Unpacks a hint, or returns `null` for a malformed one.
     *
     * The three rejections are the standard's and are the reason this returns a nullable rather than
     * throwing: a signature carrying a non-monotonic index list, a count that moves backwards or past
     * ω, or a non-zero byte in the unused tail is simply *invalid*, and [verify] must answer `false`
     * for it rather than propagate an exception to the caller.
     */
    private fun decodeHint(src: ByteArray, offset: Int): Array<IntArray>? {
        val h = Array(k) { IntArray(n) }
        var start = 0
        for (i in 0 until k) {
            val end = src[offset + omega + i].toInt() and 0xFF
            if (end < start || end > omega) return null
            for (j in start until end) {
                if (j > start && (src[offset + j].toInt() and 0xFF) <= (src[offset + j - 1].toInt() and 0xFF)) {
                    return null
                }
                h[i][src[offset + j].toInt() and 0xFF] = 1
            }
            start = end
        }
        for (j in start until omega) if (src[offset + j] != 0.toByte()) return null
        return h
    }

    // -------------------------------------------------------------------------------------------
    // Sampling (FIPS-204 §7.3)
    // -------------------------------------------------------------------------------------------

    /**
     * `RejNTTPoly` — one matrix entry `A[i][j]`, uniform over `Z_q`, sampled straight into the NTT
     * domain.
     *
     * Rejection sampling on 23-bit fields: each three bytes give one candidate, masked to 23 bits and
     * kept only if below `q`. Roughly one in fourteen is rejected, so the block count is unbounded and
     * the XOF must stream.
     *
     * The alignment guard matters: SHAKE-128's 168-byte rate is divisible by three precisely so a
     * candidate never straddles a block boundary. This is the single hottest function in the scheme —
     * ML-DSA-87 key generation samples 56 matrix entries, signing another 56 — which is why the byte
     * reads are inlined rather than routed through a helper.
     */
    private fun rejNttPoly(xof: Sha3.SeededXof): IntArray {
        val r = IntArray(n)
        var j = 0
        while (j < n) {
            val b = xof.next()
            if (b.size % 3 != 0) throw IllegalStateException("RejNTTPoly: unaligned block")
            var i = 0
            while (j < n && i + 3 <= b.size) {
                val t = ((b[i].toInt() and 0xFF) or
                    ((b[i + 1].toInt() and 0xFF) shl 8) or
                    ((b[i + 2].toInt() and 0xFF) shl 16)) and 0x7FFFFF
                if (t < q) r[j++] = t
                i += 3
            }
        }
        return r
    }

    /**
     * `CoefFromHalfByte` — a nibble to a coefficient in `[−η, η]`, or "reject".
     *
     * η = 2 maps `0..14` through `2 − (n mod 5)`, giving a uniform draw from five values and rejecting
     * 15. η = 4 maps `0..8` through `4 − n` and rejects the rest. `Int.MIN_VALUE` is the sentinel; the
     * value cannot occur as a coefficient.
     */
    private fun coefFromHalfByte(value: Int): Int =
        if (eta == 2) {
            if (value < 15) 2 - (value % 5) else Int.MIN_VALUE
        } else {
            if (value < 9) 4 - value else Int.MIN_VALUE
        }

    /**
     * `RejBoundedPoly` — a secret polynomial with coefficients in `[−η, η]`.
     *
     * Two nibbles per byte, low nibble first. Coefficients are stored **signed** here and reduced only
     * when they enter the NTT, which is what the η coder's range assertion relies on.
     */
    private fun rejBoundedPoly(xof: Sha3.SeededXof): IntArray {
        val r = IntArray(n)
        var j = 0
        while (j < n) {
            val b = xof.next()
            var i = 0
            while (j < n && i < b.size) {
                val byte = b[i].toInt() and 0xFF
                val d1 = coefFromHalfByte(byte and 0x0F)
                val d2 = coefFromHalfByte((byte ushr 4) and 0x0F)
                if (d1 != Int.MIN_VALUE) r[j++] = d1
                if (j < n && d2 != Int.MIN_VALUE) r[j++] = d2
                i++
            }
        }
        return r
    }

    /**
     * `SampleInBall` — the verifier's challenge: a polynomial with exactly τ coefficients in `{−1, 1}`
     * and the rest zero.
     *
     * A Fisher–Yates-style placement, and the order is essential. For each `i` from `n − τ` upward it
     * draws bytes until one is `≤ i`, moves whatever sits at that position out to `i`, and writes a
     * sign there taken from the *first eight bytes* of the stream — a bit at a time, LSB-first, one
     * bit per accepted position. The eight sign bytes are consumed as a fixed prefix, not interleaved
     * with the rejection stream.
     *
     * The refill condition is the reference's and reads oddly on purpose: a block is exhausted when
     * `pos` reaches the rate *after* the read, so the check follows the increment.
     */
    private fun sampleInBall(seed: ByteArray): IntArray {
        val pre = IntArray(n)
        val blockLen = 136
        val sponge = Sha3.shake256(blockLen)
        sponge.update(seed)
        val buf = ByteArray(blockLen)
        sponge.xofInto(buf)
        val masks = buf.copyOfRange(0, 8)
        var pos = 8
        var maskPos = 0
        var maskBit = 0
        for (i in n - tau until n) {
            var b = i + 1
            while (b > i) {
                b = buf[pos++].toInt() and 0xFF
                if (pos < blockLen) continue
                sponge.xofInto(buf)
                pos = 0
            }
            pre[i] = pre[b]
            pre[b] = 1 - (((masks[maskPos].toInt() ushr maskBit++) and 1) shl 1)
            if (maskBit >= 8) {
                maskPos++
                maskBit = 0
            }
        }
        sponge.destroy()
        Bytes.clean(buf, masks)
        return pre
    }

    // -------------------------------------------------------------------------------------------
    // Key generation (FIPS-204 §6.1)
    // -------------------------------------------------------------------------------------------

    /**
     * `ML-DSA.KeyGen_internal`, from a 32-byte seed.
     *
     * `(ρ, ρ′, K) ← H(seed || k || l, 128)`. The two trailing bytes are the parameter-set domain
     * separation: without them the same seed would produce related keys at 44, 65 and 87.
     *
     * `t ← NTT⁻¹(Â ∘ NTT(s1)) + s2`, then `(t1, t0) ← Power2Round(t)`. The public key carries `t1`, the
     * private one `t0` — plus `tr = H(pk, 512)`, so signing can bind the message to the public key
     * without being handed it.
     *
     * The matrix is sampled at `(j, i)` — column index into the XOF's first byte. [sign] samples the
     * same entries in the same order and must agree; it does.
     *
     * The seed belongs to the caller and is left untouched. Everything derived from it — ρ, ρ′, K, the
     * secret vectors and their NTT images — is wiped before returning.
     *
     * Deterministic, so the seed *is* the private key: 32 CSPRNG bytes, never reused across keys, wiped
     * once used. Use [keygen] with no argument unless you are deriving a key from stored material.
     */
    public fun keygen(seed: ByteArray): KeyPair {
        Bytes.requireSize(seed, seedLen, "seed")
        val seedDst = ByteArray(34)
        seed.copyInto(seedDst)
        seedDst[32] = k.toByte()
        seedDst[33] = l.toByte()
        val expanded = Sha3.shake256Of(seedDst, 128)
        val rho = expanded.copyOfRange(0, 32)
        val rhoPrime = expanded.copyOfRange(32, 96)
        val bigK = expanded.copyOfRange(96, 128)

        val xofPrime = Sha3.xof256(rhoPrime)
        val s1 = Array(l) { rejBoundedPoly(xofPrime.seek(it and 0xFF, (it shr 8) and 0xFF)) }
        val s2 = Array(k) {
            val idx = l + it
            rejBoundedPoly(xofPrime.seek(idx and 0xFF, (idx shr 8) and 0xFF))
        }
        xofPrime.clean()

        val s1Hat = Array(l) { DilithiumRing.nttEncode(s1[it].copyOf()) }
        val t0 = arrayOfNulls<IntArray>(k)
        val t1 = arrayOfNulls<IntArray>(k)
        val xof = Sha3.xof128(rho)
        val t = IntArray(n)
        for (i in 0 until k) {
            t.fill(0)
            for (j in 0 until l) multiplyNttInto(t, rejNttPoly(xof.seek(j, i)), s1Hat[j])
            DilithiumRing.nttDecode(t)
            polyAdd(t, s2[i])
            t0[i] = IntArray(n) { power2RoundLow(t[it]) }
            t1[i] = IntArray(n) { power2RoundHigh(t[it]) }
        }
        xof.clean()

        @Suppress("UNCHECKED_CAST")
        val high = t1 as Array<IntArray>

        @Suppress("UNCHECKED_CAST")
        val low = t0 as Array<IntArray>

        val publicKey = ByteArray(publicKeyLen)
        rho.copyInto(publicKey)
        t1Packer.encodeVecInto(high, publicKey, 32, k)
        val tr = Sha3.shake256Of(publicKey, trBytes)

        val secretKey = ByteArray(secretKeyLen)
        var pos = 0
        rho.copyInto(secretKey, pos); pos += 32
        bigK.copyInto(secretKey, pos); pos += 32
        tr.copyInto(secretKey, pos); pos += trBytes
        etaPacker.encodeVecInto(s1, secretKey, pos, l); pos += l * etaPacker.bytesLen
        etaPacker.encodeVecInto(s2, secretKey, pos, k); pos += k * etaPacker.bytesLen
        t0Packer.encodeVecInto(low, secretKey, pos, k)

        Bytes.clean(seedDst, expanded, rho, rhoPrime, bigK, tr)
        Bytes.cleanPolys(t)
        Bytes.cleanPolys(*s1); Bytes.cleanPolys(*s2); Bytes.cleanPolys(*s1Hat)
        Bytes.cleanPolys(*high); Bytes.cleanPolys(*low)
        return KeyPair(publicKey, secretKey)
    }

    /**
     * As [keygen], with a freshly generated seed.
     *
     * The generated seed is wiped once the key exists, which a default argument could not do — it
     * would leave the 32 bytes that reproduce the whole private key live in the caller's frame.
     */
    public fun keygen(): KeyPair {
        val seed = Bytes.random(seedLen)
        try {
            return keygen(seed)
        } finally {
            Bytes.clean(seed)
        }
    }

    // -------------------------------------------------------------------------------------------
    // Signing (FIPS-204 §6.2)
    // -------------------------------------------------------------------------------------------

    /** The six fields of an encoded secret key, unpacked once per signature. */
    private class SecretKey(
        val rho: ByteArray,
        val bigK: ByteArray,
        val tr: ByteArray,
        val s1: Array<IntArray>,
        val s2: Array<IntArray>,
        val t0: Array<IntArray>,
    )

    private fun decodeSecretKey(secretKey: ByteArray): SecretKey {
        Bytes.requireSize(secretKey, secretKeyLen, "secretKey")
        var pos = 0
        val rho = secretKey.copyOfRange(pos, pos + 32); pos += 32
        val bigK = secretKey.copyOfRange(pos, pos + 32); pos += 32
        val tr = secretKey.copyOfRange(pos, pos + trBytes); pos += trBytes
        val s1 = etaPacker.decodeVec(secretKey, pos, l); pos += l * etaPacker.bytesLen
        val s2 = etaPacker.decodeVec(secretKey, pos, k); pos += k * etaPacker.bytesLen
        val t0 = t0Packer.decodeVec(secretKey, pos, k)
        return SecretKey(rho, bigK, tr, s1, s2, t0)
    }

    /**
     * `ML-DSA.Sign_internal` — signs [msg] exactly as given, with no domain prefix.
     *
     * [extraEntropy] is the per-signature randomness `rnd`. Left null it is 32 fresh random bytes,
     * which is the default and means two signatures over the same message differ. Passing 32 zero
     * bytes gives the deterministic ("hedged off") variant; both verify identically, and the choice is
     * invisible to a verifier.
     *
     * The rejection loop can in principle run many times — the expected count is about 4.25 at these
     * parameters — and κ advances by `l` on every attempt, so the mask is fresh each time. There is no
     * iteration cap because a bound that could be hit would be a correctness bug: the loop terminates
     * with probability 1 and the reference has no cap either.
     *
     * FIPS-204 §5.4 exposes this only "for testing and validation"; the same warning applies here. It
     * is *not* [sign] without a context — it signs the bytes you hand it, so a service that will sign an
     * arbitrary message with this becomes a forgery oracle for the real API: `signInternal(00 00 X)`
     * *is* a valid `sign(X)` under the empty context. Use it to drive ACVP's internal-interface vectors,
     * or when you build FIPS-204's §5 envelope yourself. Otherwise use [sign].
     */
    public fun signInternal(
        msg: ByteArray,
        secretKey: ByteArray,
        extraEntropy: ByteArray? = null,
    ): ByteArray {
        // Entropy is prepared *before* the key is touched, and the order is deliberate: both
        // `Bytes.random` and the `extraEntropy` length check can throw, and neither must leave an
        // expanded copy of a private key behind. Getting it the other way round means a caller who
        // passes 31 bytes — or an environment whose CSPRNG fails — strands ρ, K, tr, µ and 23
        // NTT-domain secret polynomials in the heap. The reference orders it the same way for the
        // same reason, and pins it in `ML-DSA prepares and cleans entropy before secret expansion`.
        val rnd = extraEntropy ?: Bytes.random(32)
        val sk = try {
            Bytes.requireSize(rnd, 32, "extraEntropy")
            decodeSecretKey(secretKey)
        } catch (e: Throwable) {
            // Only randomness this function generated is wiped; a caller's array stays the caller's.
            if (extraEntropy == null) Bytes.clean(rnd)
            throw e
        }

        // A ← ExpandA(ρ), cached whole: the loop below may re-run and must not resample it.
        val a = Array(k) { arrayOfNulls<IntArray>(l) }
        val xofA = Sha3.xof128(sk.rho)
        for (i in 0 until k) for (j in 0 until l) a[i][j] = rejNttPoly(xofA.seek(j, i))
        xofA.clean()

        @Suppress("UNCHECKED_CAST")
        val matrix = a as Array<Array<IntArray>>

        for (i in 0 until l) DilithiumRing.nttEncode(sk.s1[i])
        for (i in 0 until k) {
            DilithiumRing.nttEncode(sk.s2[i])
            DilithiumRing.nttEncode(sk.t0[i])
        }

        // µ ← H(tr || M, 512)
        val mu = Sha3.shake256(crhBytes).update(sk.tr).update(msg).digest()
        // ρ′ ← H(K || rnd || µ, 512)
        val rhoPrime = Sha3.shake256(crhBytes).update(sk.bigK).update(rnd).update(mu).digest()
        if (extraEntropy == null) Bytes.clean(rnd)
        // ρ, K and tr have all been consumed — the XOF copied ρ, ρ′ absorbed K, µ absorbed tr — and
        // these are this function's own copies of the key material, so they are wiped now rather
        // than at the (unbounded) end of the rejection loop.
        Bytes.clean(sk.rho, sk.bigK, sk.tr)

        val x256 = Sha3.xof256(rhoPrime, zPacker.bytesLen)
        var kappa = 0
        while (true) {
            // y ← ExpandMask(ρ′, κ)
            val y = Array(l) {
                val block = x256.seek(kappa and 0xFF, kappa shr 8).next()
                kappa++
                zPacker.decode(block, 0)
            }
            val z = Array(l) { DilithiumRing.nttEncode(y[it].copyOf()) }

            // w ← NTT⁻¹(Â ∘ ŷ)
            val w = Array(k) { i ->
                val wi = IntArray(n)
                for (j in 0 until l) multiplyNttInto(wi, matrix[i][j], z[j])
                DilithiumRing.nttDecode(wi)
            }
            val w1 = Array(k) { i -> IntArray(n) { highBits(w[i][it]) } }

            // c̃ ← H(µ || w1Encode(w1), 2λ)
            val w1Encoded = ByteArray(w1VecLen)
            w1Packer.encodeVecInto(w1, w1Encoded, 0, k)
            val cTilde = Sha3.shake256(cTildeBytes).update(mu).update(w1Encoded).digest()
            val cHat = DilithiumRing.nttEncode(sampleInBall(cTilde))

            // z ← y + ⟨⟨c·s1⟩⟩, rejected on ‖z‖∞ ≥ γ₁ − β
            val zOut = Array(l) { multiplyNtt(sk.s1[it], cHat) }
            var reject = false
            for (i in 0 until l) {
                polyAdd(DilithiumRing.nttDecode(zOut[i]), y[i])
                if (polyChknorm(zOut[i], gamma1 - beta)) {
                    reject = true
                    break
                }
            }

            if (!reject) {
                var count = 0
                val h = arrayOfNulls<IntArray>(k)
                for (i in 0 until k) {
                    // r0 ← LowBits(w − ⟨⟨c·s2⟩⟩)
                    //
                    // `cs2` is `c·s2` and `ct0` is `c·t0` with `c` public — a verifier recomputes it
                    // from the signature's own c̃ — and a sparse ±1 challenge is invertible, so a
                    // surviving copy of either is the secret it was multiplied by. Both are wiped the
                    // moment they are dead, on every one of the three exits below as well as the fall
                    // through, because this loop runs about 4.25 times per signature and an abandoned
                    // array is readable until the collector happens to reuse the page.
                    val cs2 = DilithiumRing.nttDecode(multiplyNtt(sk.s2[i], cHat))
                    val r0 = polySub(w[i], cs2).let { diff -> IntArray(n) { lowBits(diff[it]) } }
                    Bytes.cleanPolys(cs2)
                    if (polyChknorm(r0, gamma2 - beta)) {
                        Bytes.cleanPolys(r0)
                        reject = true
                        break
                    }
                    val ct0 = DilithiumRing.nttDecode(multiplyNtt(sk.t0[i], cHat))
                    if (polyChknorm(ct0, gamma2)) {
                        Bytes.cleanPolys(r0, ct0)
                        reject = true
                        break
                    }
                    polyAdd(r0, ct0)
                    // h ← MakeHint(−⟨⟨c·t0⟩⟩, w − ⟨⟨c·s2⟩⟩ + ⟨⟨c·t0⟩⟩)
                    val hi = IntArray(n)
                    for (j in 0 until n) {
                        val bit = makeHint(r0[j], w1[i][j])
                        hi[j] = bit
                        count += bit
                    }
                    h[i] = hi
                    Bytes.cleanPolys(r0, ct0)
                }
                // The number of set hint bits must fit the ω budget the encoding allows.
                if (!reject && count <= omega) {
                    x256.clean()
                    val signature = ByteArray(signatureLen)
                    cTilde.copyInto(signature)
                    zPacker.encodeVecInto(zOut, signature, cTildeBytes, l)
                    @Suppress("UNCHECKED_CAST")
                    encodeHint(h as Array<IntArray>, signature, cTildeBytes + zVecLen)
                    Bytes.clean(mu, rhoPrime, cTilde, w1Encoded)
                    Bytes.cleanPolys(*sk.s1); Bytes.cleanPolys(*sk.s2); Bytes.cleanPolys(*sk.t0)
                    Bytes.cleanPolys(*y); Bytes.cleanPolys(*z); Bytes.cleanPolys(*w)
                    Bytes.cleanPolys(*w1)
                    Bytes.cleanPolys(*zOut); Bytes.cleanPolys(*h); Bytes.cleanPolys(cHat)
                    for (row in matrix) Bytes.cleanPolys(*row)
                    return signature
                }
                // A hint row is `MakeHint` over secret-derived material; the rows already filled are
                // wiped whether the row loop broke early or the ω budget overflowed.
                for (row in h) if (row != null) Bytes.cleanPolys(row)
            }
            Bytes.clean(cTilde, w1Encoded)
            Bytes.cleanPolys(cHat)
            Bytes.cleanPolys(*y); Bytes.cleanPolys(*z); Bytes.cleanPolys(*w); Bytes.cleanPolys(*w1)
            Bytes.cleanPolys(*zOut)
        }
    }

    // -------------------------------------------------------------------------------------------
    // Verification (FIPS-204 §6.3)
    // -------------------------------------------------------------------------------------------

    /**
     * `ML-DSA.Verify_internal` — checks [sig] over [msg] exactly as given, with no domain prefix.
     *
     * Returns `false` for every *cryptographic* rejection and for a structurally malformed signature —
     * wrong length, a hint that does not decode, a response over the norm bound. A wrong-length public
     * key is a caller error rather than a failed verification and throws, which is the distinction the
     * library draws too: the signature is attacker-supplied and must never raise, the key is not.
     *
     * The check reconstructs `w′ ← UseHint(h, A·z − c·t1·2^d)` and re-derives the commitment hash from
     * it. Equality with the transmitted `c̃` is the signature. The two norm checks and the ω budget are
     * FIPS-204's additional conditions and are applied even though a well-formed signature always
     * satisfies them.
     *
     * As with [signInternal], FIPS-204 §5.4 means this for testing and validation. It verifies bare
     * bytes, so it accepts the `00 00 X` envelope [verify] builds as a plain message — which is exactly
     * how a `signInternal` oracle turns into forged `sign` signatures. Prefer [verify].
     */
    public fun verifyInternal(sig: ByteArray, msg: ByteArray, publicKey: ByteArray): Boolean {
        Bytes.requireSize(publicKey, publicKeyLen, "publicKey")
        val rho = publicKey.copyOfRange(0, 32)
        val t1 = t1Packer.decodeVec(publicKey, 32, k)
        val tr = Sha3.shake256Of(publicKey, trBytes)

        if (sig.size != signatureLen) return false
        val cTilde = sig.copyOfRange(0, cTildeBytes)
        val z = zPacker.decodeVec(sig, cTildeBytes, l)
        val h = decodeHint(sig, cTildeBytes + zVecLen) ?: return false

        for (i in 0 until l) if (polyChknorm(z[i], gamma1 - beta)) return false

        val mu = Sha3.shake256(crhBytes).update(tr).update(msg).digest()
        val c = DilithiumRing.nttEncode(sampleInBall(cTilde))
        val zHat = Array(l) { DilithiumRing.nttEncode(z[it].copyOf()) }

        val wTick1 = arrayOfNulls<IntArray>(k)
        val xof = Sha3.xof128(rho)
        for (i in 0 until k) {
            // c · t1 · 2^d, in the NTT domain
            val ct12d = multiplyNtt(DilithiumRing.nttEncode(polyShiftl(t1[i])), c)
            val az = IntArray(n)
            for (j in 0 until l) multiplyNttInto(az, rejNttPoly(xof.seek(j, i)), zHat[j])
            val wApprox = DilithiumRing.nttDecode(polySub(az, ct12d))
            for (j in 0 until n) wApprox[j] = useHint(h[i][j], wApprox[j])
            wTick1[i] = wApprox
        }
        xof.clean()

        @Suppress("UNCHECKED_CAST")
        val reconstructed = wTick1 as Array<IntArray>
        val w1Encoded = ByteArray(w1VecLen)
        w1Packer.encodeVecInto(reconstructed, w1Encoded, 0, k)
        val c2 = Sha3.shake256(cTildeBytes).update(mu).update(w1Encoded).digest()

        for (hi in h) {
            var sum = 0
            for (v in hi) sum += v
            if (sum > omega) return false
        }
        for (zi in z) if (polyChknorm(zi, gamma1 - beta)) return false
        return Bytes.equal(cTilde, c2)
    }

    // -------------------------------------------------------------------------------------------
    // Public API (FIPS-204 §5) — the domain-separated wrapper
    // -------------------------------------------------------------------------------------------

    /**
     * Signs `0x00 || len(ctx) || ctx || msg`.
     *
     * The envelope is the difference between this and [signInternal], and it is mandatory: FIPS-204's
     * §5 API is defined over the prefixed message, so a signature made over the bare bytes verifies
     * against nothing. With the empty context the prefix is the two bytes `00 00`.
     *
     * `context` is domain separation, up to 255 bytes; it must match at [verify], and 256 bytes throws
     * rather than being truncated. `extraEntropy` is the per-signature `rnd`: left null it is 32 fresh
     * random bytes (hedged signing, the default), and 32 zero bytes gives FIPS-204 §3.4's deterministic
     * variant. A verifier cannot tell which was used.
     */
    public fun sign(
        msg: ByteArray,
        secretKey: ByteArray,
        context: ByteArray = Bytes.EMPTY,
        extraEntropy: ByteArray? = null,
    ): ByteArray {
        val envelope = Bytes.signedMessage(msg, context)
        val sig = signInternal(envelope, secretKey, extraEntropy)
        Bytes.clean(envelope)
        return sig
    }

    /**
     * Verifies against the same `0x00 || len(ctx) || ctx || msg` envelope [sign] produces.
     *
     * `false` is every cryptographic and structural rejection; a wrong-length [publicKey] or a
     * `context` over 255 bytes throws, both being caller errors rather than failed verifications.
     */
    public fun verify(
        sig: ByteArray,
        msg: ByteArray,
        publicKey: ByteArray,
        context: ByteArray = Bytes.EMPTY,
    ): Boolean = verifyInternal(sig, Bytes.signedMessage(msg, context), publicKey)
}

/**
 * ML-DSA-44 — FIPS-204 Table 1, category-2 security. `(k, l) = (4, 4)`, λ = 128.
 *
 * The three sets are not interchangeable: the `seed || k || l` domain separation in [MlDsa.keygen]
 * means one seed gives three unrelated keypairs, and [MlDsa.signatureLen] differs, so a mismatched
 * verifier rejects on length rather than silently.
 */
public val mlDsa44: MlDsa = MlDsa(
    k = 4,
    l = 4,
    gamma1 = 1 shl 17,
    gamma2 = GAMMA2_1,
    tau = 39,
    eta = 2,
    omega = 80,
    cTildeBytes = 32,
    crhBytes = 64,
    trBytes = 64,
)

/** ML-DSA-65 — FIPS-204 Table 1, category-3 security. `(k, l) = (6, 5)`, λ = 192. The usual default. */
public val mlDsa65: MlDsa = MlDsa(
    k = 6,
    l = 5,
    gamma1 = 1 shl 19,
    gamma2 = GAMMA2_2,
    tau = 49,
    eta = 4,
    omega = 55,
    cTildeBytes = 48,
    crhBytes = 64,
    trBytes = 64,
)

/** ML-DSA-87 — FIPS-204 Table 1, category-5 security. `(k, l) = (8, 7)`, λ = 256. */
public val mlDsa87: MlDsa = MlDsa(
    k = 8,
    l = 7,
    gamma1 = 1 shl 19,
    gamma2 = GAMMA2_2,
    tau = 60,
    eta = 2,
    omega = 75,
    cTildeBytes = 64,
    crhBytes = 64,
    trBytes = 64,
)
