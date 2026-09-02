package io.github.mortezajavadian.pq.lattice

import java.math.BigInteger

/**
 * The shared lattice arithmetic of ML-KEM and ML-DSA: the ring `Z_q[x]/(x^256 + 1)`, its
 * number-theoretic transform, and the two modular reductions the schemes are written in terms of.
 *
 * Both schemes are the same algebra with different constants, so both get one instance of this class
 * ([Kyber] and [Dilithium]) rather than two copies of the transform. What differs is only:
 *
 * | | ML-KEM | ML-DSA |
 * |---|---|---|
 * | `q` | 3329 (12 bits) | 8380417 (23 bits) |
 * | `f` = n⁻¹ | 3303 (=128⁻¹) | 8347681 (=256⁻¹) |
 * | root of unity ζ | 17 | 1753 |
 * | ζ-table index width | 7 bits | 8 bits |
 * | skipped NTT stage | 1 | 0 |
 *
 * **Why ML-KEM skips a stage and divides by 128 instead of 256.** There is no 512th primitive root
 * of unity mod 3329, only a 256th, so the negacyclic transform cannot be carried to single
 * coefficients — it stops one level early, leaving 128 degree-one polynomials. That is also why
 * multiplication in the NTT domain is not pointwise for ML-KEM (see `MlKem`'s `multiplyNtt`) while it
 * is for ML-DSA.
 *
 * **Reduction is by `%`, not Montgomery.** A 23-bit modulus times a 23-bit coefficient is 46 bits,
 * which is exact in a 64-bit register, so `%` gives the mathematically correct residue with no
 * conditioning and no extra state. Montgomery form would be faster in a C implementation that can
 * keep coefficients in registers across a whole polynomial, but it also changes the intermediate
 * representation, and any divergence there would change key bytes. The measured cost is not where
 * the time goes: both schemes spend the large majority of their time in SHAKE.
 *
 * Every method is pure or mutates only its argument, so instances are stateless after construction
 * and safe to share across threads.
 */
internal abstract class Crystals(
    /** Polynomial degree; 256 in every standardised parameter set. */
    val n: Int,
    /** The prime modulus. */
    val q: Int,
    /** `n⁻¹ mod q` for ML-DSA, `(n/2)⁻¹ mod q` for ML-KEM — the inverse-NTT scale factor. */
    val f: Int,
    rootOfUnity: Int,
    brvBits: Int,
    /** 1 for ML-KEM, 0 for ML-DSA. See the class note. */
    private val skipStages: Int,
) {

    /**
     * `ζ^bitReverse(i)` for `i` in `0 until n`.
     *
     * Bit-reversed rather than sequential because that is the order the in-place transform visits
     * them in, which removes the permutation pass entirely: the butterflies read `zetas[group]`
     * with `group` simply incrementing. Computed with [BigInteger] at construction because
     * `1753^255` overflows every fixed-width type; it happens once per process.
     */
    val zetas: IntArray = IntArray(n).also { out ->
        val modulus = BigInteger.valueOf(q.toLong())
        val root = BigInteger.valueOf(rootOfUnity.toLong())
        for (i in 0 until n) {
            val exponent = reverseBits(i, brvBits)
            out[i] = root.modPow(BigInteger.valueOf(exponent.toLong()), modulus).toInt()
        }
    }

    private val stages = Integer.numberOfTrailingZeros(n)

    // -------------------------------------------------------------------------------------------
    // Reduction
    // -------------------------------------------------------------------------------------------

    /** Least non-negative residue, `a mod q`. */
    fun mod(a: Int): Int {
        val r = a % q
        return if (r >= 0) r else q + r
    }

    /** As [mod], for a product that does not fit in 32 bits. */
    fun mod(a: Long): Int {
        val r = (a % q).toInt()
        return if (r >= 0) r else q + r
    }

    /** Least non-negative residue for an arbitrary modulus; used by `UseHint`. */
    fun mod(a: Int, modulo: Int): Int {
        val r = a % modulo
        return if (r >= 0) r else modulo + r
    }

    /**
     * The signed representative in `(-(q-1)/2, (q-1)/2]`.
     *
     * Distinct from [mod] and not interchangeable with it: the schemes' norm checks, the `z`
     * encoding and both decompositions are defined on the signed residue, and using [mod] there
     * would reject valid signatures and mis-pack keys.
     */
    fun smod(a: Int): Int {
        val r = mod(a)
        return if (r > q shr 1) r - q else r
    }

    /** As [smod], for the sub-moduli `2γ₂` and `2^d`. */
    fun smod(a: Int, modulo: Int): Int {
        val r = mod(a, modulo)
        return if (r > modulo shr 1) r - modulo else r
    }

    // -------------------------------------------------------------------------------------------
    // NTT
    // -------------------------------------------------------------------------------------------

    /**
     * Forward transform, in place, natural input → bit-reversed output.
     *
     * Decimation-in-frequency loop with the standard butterfly, top-down: stage lengths run from `n`
     * down to `2^(1 + skipStages)`. The `group` counter advances once per sub-array and is the ζ
     * index, which is what makes the bit-reversed [zetas] table the right one.
     *
     * No bit-reversal permutation on either side. Both schemes consume NTT-domain values only by
     * multiplying them against each other, and the permutation is the same on both operands, so it
     * cancels — omitting it is free and is what the reference implementations do too.
     */
    fun nttEncode(r: IntArray): IntArray {
        var group = 1
        for (stage in 0 until stages - skipStages) {
            val s = stages - stage
            val m = 1 shl s
            val half = m shr 1
            var k = 0
            while (k < n) {
                val omega = zetas[group++].toLong()
                for (j in 0 until half) {
                    val i0 = k + j
                    val i1 = i0 + half
                    val t = mod(r[i1] * omega)
                    val a = r[i0]
                    r[i0] = mod(a + t)
                    r[i1] = mod(a - t)
                }
                k += m
            }
        }
        return r
    }

    /**
     * Inverse transform, in place, then the `f` scaling.
     *
     * Decimation-in-time loop with **inverted** butterflies — `(a, b) ↦ (b + a, (b − a)·ω)` — walking
     * bottom-up, which is the exact dual of [nttEncode] and therefore needs no permutation either.
     * The ζ index counts *down* from `n`, which is how the table of forward roots serves as the table
     * of inverse roots: `zetas[n - group]` is `ζ^(-bitReverse(group))`.
     *
     * The final multiply by [f] is the `1/n` (or `1/128`) an inverse transform owes; it is folded
     * into one pass over the coefficients rather than into the butterflies.
     */
    fun nttDecode(r: IntArray): IntArray {
        var group = 1
        for (stage in 0 until stages - skipStages) {
            val s = stage + 1 + skipStages
            val m = 1 shl s
            val half = m shr 1
            var k = 0
            while (k < n) {
                val omega = zetas[n - group++].toLong()
                for (j in 0 until half) {
                    val i0 = k + j
                    val i1 = i0 + half
                    val a = r[i0]
                    val b = r[i1]
                    r[i0] = mod(b + a)
                    r[i1] = mod((b - a) * omega)
                }
                k += m
            }
        }
        val scale = f.toLong()
        for (i in r.indices) r[i] = mod(scale * r[i])
        return r
    }

    companion object {
        /** Reverses the low [bits] bits of [value]; the ζ-table index map. */
        fun reverseBits(value: Int, bits: Int): Int {
            var n = value
            var reversed = 0
            for (i in 0 until bits) {
                reversed = (reversed shl 1) or (n and 1)
                n = n ushr 1
            }
            return reversed
        }
    }
}
