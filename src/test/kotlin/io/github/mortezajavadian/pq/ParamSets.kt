package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.mldsa.MlDsa
import io.github.mortezajavadian.pq.mlkem.MlKem

/**
 * All six standardised parameter sets, so the suite validates the whole of FIPS 203 and FIPS 204
 * and not only the two rows the originating app ships.
 *
 * Every one of them is the library's own instance — `mlKem512/768/1024` and `mlDsa44/65/87` as
 * published, not a copy built here from the same table. That is the point: if the vectors passed
 * against locally constructed instances, they would prove the constructors are parameterised while
 * saying nothing about the six values a consumer actually gets. NIST's own files now check the shipped
 * objects.
 */
internal object Params {
    /** FIPS 203 Table 2: `k=2, η1=3, η2=2, du=10, dv=4`; sizes 800 / 1632 / 768. */
    val mlKem512: MlKem = io.github.mortezajavadian.pq.mlkem.mlKem512

    /** FIPS 203 Table 2: `k=3, η1=2, η2=2, du=10, dv=4`; sizes 1184 / 2400 / 1088. */
    val mlKem768: MlKem = io.github.mortezajavadian.pq.mlkem.mlKem768

    /** FIPS 203 Table 2: `k=4, η1=2, η2=2, du=11, dv=5`; sizes 1568 / 3168 / 1568. */
    val mlKem1024: MlKem = io.github.mortezajavadian.pq.mlkem.mlKem1024

    /** FIPS 204 Table 1, category 2: `k=4, ℓ=4, γ1=2^17, γ2=(q−1)/88, τ=39, η=2, ω=80`. */
    val mlDsa44: MlDsa = io.github.mortezajavadian.pq.mldsa.mlDsa44

    /** FIPS 204 Table 1, category 3: `k=6, ℓ=5, γ1=2^19, γ2=(q−1)/32, τ=49, η=4, ω=55`. */
    val mlDsa65: MlDsa = io.github.mortezajavadian.pq.mldsa.mlDsa65

    /** FIPS 204 Table 1, category 5: `k=8, ℓ=7, γ1=2^19, γ2=(q−1)/32, τ=60, η=2, ω=75`. */
    val mlDsa87: MlDsa = io.github.mortezajavadian.pq.mldsa.mlDsa87

    /** Keyed by the `parameterSet` string ACVP puts on every group. */
    val kemByAcvpName: Map<String, MlKem> = linkedMapOf(
        "ML-KEM-512" to mlKem512,
        "ML-KEM-768" to mlKem768,
        "ML-KEM-1024" to mlKem1024,
    )

    val dsaByAcvpName: Map<String, MlDsa> = linkedMapOf(
        "ML-DSA-44" to mlDsa44,
        "ML-DSA-65" to mlDsa65,
        "ML-DSA-87" to mlDsa87,
    )

    /** Wycheproof names its files by the bare level: `mlkem_512_test`, `mldsa_44_verify_test`. */
    val kemLevels: List<Pair<String, MlKem>> =
        listOf("512" to mlKem512, "768" to mlKem768, "1024" to mlKem1024)

    val dsaLevels: List<Pair<String, MlDsa>> =
        listOf("44" to mlDsa44, "65" to mlDsa65, "87" to mlDsa87)

    /**
     * `ω` and `k` per set, for the hint-encoding tests. Both are constructor arguments the library
     * keeps private, and the malformed-hint cases need them to find the hint field inside a
     * signature; the reference suite carries the same literal table for the same reason.
     */
    val dsaHintShape: List<Triple<MlDsa, Int, Int>> = listOf(
        Triple(mlDsa44, 80, 4),
        Triple(mlDsa65, 55, 6),
        Triple(mlDsa87, 75, 8),
    )
}

/**
 * The public key of an ML-KEM decapsulation key, which FIPS 203 stores inside it verbatim at
 * `dk[384k … 384k + |ek|]`.
 *
 * The library has no `getPublicKey`, so the ACVP `decapsulationKeyCheck` group — which asserts a
 * decapsulation key really does carry the matching encapsulation key — reads the slice here. This is
 * a test-side accessor over a documented layout, not a reimplementation: the ML-DSA equivalent
 * *would* be a reimplementation (t1 is not stored in a signing key; recovering it means recomputing
 * `A·s1 + s2` and rounding), which is why that assertion is skipped and reported instead.
 */
internal fun MlKem.publicKeyOf(secretKey: ByteArray): ByteArray =
    secretKey.copyOfRange(kpkeSecretKeyLen, kpkeSecretKeyLen + publicKeyLen)
