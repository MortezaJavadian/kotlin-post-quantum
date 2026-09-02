package io.github.mortezajavadian.pq.mldsa

import io.github.mortezajavadian.pq.lattice.IntCoder

/**
 * The per-coefficient maps ML-DSA packs its keys and signatures with.
 *
 * Each is a bijection between a signed ring coefficient and the unsigned bit-field that goes on the
 * wire, applied by `BitPacker` at a field width chosen so the field exactly covers the coefficient's
 * range. All four are involutions of the form `constant − value`, which is why encode and decode
 * share one expression: packing and unpacking are the same arithmetic.
 *
 * `t1` (10 bits) and `w1` (4 or 6 bits) need no map at all and use the identity coder.
 */

/**
 * The secret vectors `s1` and `s2`: coefficients in `[−η, η]` stored as `η − value`, so the range
 * `[−2, 2]` becomes `[0, 4]` and fits in three bits (four bits when η = 4).
 *
 * The range assertion is the library's and is load-bearing on decode, not just on encode: a
 * three-bit field can hold `5..7`, which no valid key produces, and a malformed secret key that
 * decoded silently to an out-of-range coefficient would sign garbage rather than fail. So it is
 * checked on the *decoded* value in both directions — `encode` validates its input and `decode`
 * validates its output.
 */
internal class EtaCoder(private val eta: Int) : IntCoder {
    override fun encode(value: Int): Int = eta - verify(value)
    override fun decode(value: Int): Int = verify(eta - value)

    private fun verify(i: Int): Int {
        if (i < -eta || i > eta) {
            throw IllegalArgumentException(
                "malformed key s1/s2 $i outside of ETA range [${-eta}, $eta]"
            )
        }
        return i
    }
}

/**
 * The low half of `t`: `2^(d−1) − value`, thirteen bits.
 *
 * `Power2Round` leaves `t0` in `(−2^12, 2^12]`, so the offset centres it on `[0, 2^13)` exactly.
 */
internal object T0Coder : IntCoder {
    private const val OFFSET = 1 shl (DSA_D - 1)
    override fun encode(value: Int): Int = OFFSET - value
    override fun decode(value: Int): Int = OFFSET - value
}

/**
 * The signature's response vector `z`: `smod(γ₁ − value)`, at 18 bits for γ₁ = 2^17 and 20 for 2^19.
 *
 * The [Crystals.smod] is what makes this work in both directions. `z` arrives as a least-non-negative
 * residue mod `q`, so `γ₁ − z` can land far outside the field width; reducing to the *signed*
 * representative brings it back to `[0, 2γ₁)` before the packer's mask truncates. On the way out the
 * same expression recovers the signed coefficient the norm check in `verify` needs.
 *
 * This is the one coder where using the unsigned reduction instead would still produce a
 * correctly-sized signature — and it would verify nowhere.
 */
internal class ZCoder(private val gamma1: Int) : IntCoder {
    override fun encode(value: Int): Int = DilithiumRing.smod(gamma1 - value)
    override fun decode(value: Int): Int = DilithiumRing.smod(gamma1 - value)
}
