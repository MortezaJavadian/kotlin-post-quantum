package io.github.mortezajavadian.pq.mldsa

import io.github.mortezajavadian.pq.lattice.Crystals

/**
 * ML-DSA's ring: `Z_8380417[x]/(x^256 + 1)`.
 *
 * Unlike ML-KEM's modulus, 8380417 admits a 512th primitive root of unity (1753), so the transform
 * runs all the way down to single coefficients — `skipStages = 0` — and multiplication in the NTT
 * domain is a plain pointwise product. That is the whole structural difference between the two
 * schemes' arithmetic; everything else is the same butterflies with different constants.
 *
 * `f = 8347681 = 256⁻¹ mod q`, the full `1/n` an inverse transform of length 256 owes.
 *
 * The modulus is 23 bits, so a coefficient product is 46 bits. That is inside a `Long` exactly, which
 * is why [Crystals] reduces with `%` on a `Long` and needs neither Montgomery form nor Barrett
 * conditioning — the residue is mathematically correct with no representation change that could shift
 * a key byte.
 */
internal object DilithiumRing : Crystals(
    n = 256,
    q = 8380417,
    f = 8347681,
    rootOfUnity = 1753,
    brvBits = 8,
    skipStages = 0,
)

/**
 * The `d` of FIPS-204: `t` is split as `t1·2^13 + t0`, the high half going in the public key and the
 * low half in the private one. Fixed at 13 for all three parameter sets.
 */
internal const val DSA_D: Int = 13

/** `⌊(q−1)/88⌋`, the γ₂ of ML-DSA-44. */
internal const val GAMMA2_1: Int = (8380417 - 1) / 88

/** `⌊(q−1)/32⌋`, the γ₂ of ML-DSA-65 and ML-DSA-87. */
internal const val GAMMA2_2: Int = (8380417 - 1) / 32
