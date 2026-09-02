package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.testing.Check
import io.github.mortezajavadian.pq.testing.Suite
import io.github.mortezajavadian.pq.testing.eachCase
import io.github.mortezajavadian.pq.testing.has
import io.github.mortezajavadian.pq.testing.hex
import io.github.mortezajavadian.pq.testing.isValid
import io.github.mortezajavadian.pq.testing.requiringVectors
import io.github.mortezajavadian.pq.testing.suite

/**
 * ML-KEM against Project Wycheproof.
 *
 * ACVP answers "does this compute the standard's function?". Wycheproof answers the complementary
 * question: "does this reject what it must reject?". Its ML-KEM files are mostly negative — malleable
 * ciphertexts, coefficients at and above the modulus, keys of the wrong length, a decapsulation key
 * whose embedded hash does not match — and the correct behaviour on each is a rejection, which no
 * amount of self-consistency testing can discover.
 *
 * The four files per parameter set, and what each one is for:
 *
 *  - `keygen_seed_test` — seed to key, the same ground the ACVP keyGen suite covers, from a second
 *    independent source.
 *  - `test` — decapsulation from a seed-derived key.
 *  - `encaps_test` — encapsulation with a supplied message, including invalid encapsulation keys.
 *  - `semi_expanded_decaps_test` — decapsulation from a *supplied* expanded key. This is the path a
 *    key arriving from another implementation actually takes, and it is the only negative coverage
 *    that path has: the malleable-ciphertext cases here are what catch a re-encryption comparison
 *    that is subtly wrong.
 */
internal val wycheproofMlKemSuite: Suite = suite("Wycheproof ML-KEM") {

    for ((level, kem) in Params.kemLevels) {
        test("ML-KEM-$level keygen") {
            requiringVectors {
                eachCase("mlkem_${level}_keygen_seed_test") { t, at ->
                    if (t.isValid()) {
                        val keys = kem.keygen(t.hex("seed"))
                        Check.eq(keys.publicKey, t.hex("ek"), "$at ek")
                        if (t.has("dk")) Check.eq(keys.secretKey, t.hex("dk"), "$at dk")
                    } else {
                        Check.throws(at) { kem.keygen(t.hex("seed")) }
                    }
                }
            }
        }

        test("ML-KEM-$level decaps") {
            requiringVectors {
                eachCase("mlkem_${level}_test") { t, at ->
                    if (t.isValid()) {
                        val keys = kem.keygen(t.hex("seed"))
                        Check.eq(keys.publicKey, t.hex("ek"), "$at ek")
                        Check.eq(kem.decapsulate(t.hex("c"), keys.secretKey), t.hex("K"), "$at K")
                    } else {
                        Check.throws(at) {
                            val keys = kem.keygen(t.hex("seed"))
                            kem.decapsulate(t.hex("c"), keys.secretKey)
                        }
                    }
                }
            }
        }

        test("ML-KEM-$level encaps") {
            requiringVectors {
                eachCase("mlkem_${level}_encaps_test") { t, at ->
                    if (t.isValid()) {
                        val r = kem.encapsulate(t.hex("ek"), t.hex("m"))
                        Check.eq(r.cipherText, t.hex("c"), "$at c")
                        Check.eq(r.sharedSecret, t.hex("K"), "$at K")
                    } else {
                        Check.throws(at) { kem.encapsulate(t.hex("ek"), t.hex("m")) }
                    }
                }
            }
        }

        test("ML-KEM-$level decaps (expanded key)") {
            requiringVectors {
                eachCase("mlkem_${level}_semi_expanded_decaps_test") { t, at ->
                    if (t.isValid()) {
                        Check.eq(kem.decapsulate(t.hex("c"), t.hex("dk")), t.hex("K"), "$at K")
                    } else {
                        Check.throws(at) { kem.decapsulate(t.hex("c"), t.hex("dk")) }
                    }
                }
            }
        }
    }
}
