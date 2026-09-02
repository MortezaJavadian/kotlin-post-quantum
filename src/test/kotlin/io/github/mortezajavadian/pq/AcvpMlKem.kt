package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.core.Bytes
import io.github.mortezajavadian.pq.testing.Check
import io.github.mortezajavadian.pq.testing.Skips
import io.github.mortezajavadian.pq.testing.Suite
import io.github.mortezajavadian.pq.testing.Tally
import io.github.mortezajavadian.pq.testing.acvp
import io.github.mortezajavadian.pq.testing.bool
import io.github.mortezajavadian.pq.testing.capped
import io.github.mortezajavadian.pq.testing.hex
import io.github.mortezajavadian.pq.testing.hexOrNull
import io.github.mortezajavadian.pq.testing.requiringVectors
import io.github.mortezajavadian.pq.testing.suite

/**
 * ML-KEM against NIST's own ACVP vectors — `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`,
 * all three parameter sets, every group and every case.
 *
 * These are the vectors the Cryptographic Algorithm Validation Program uses, joined from
 * `prompt.json` to `expectedResults.json` so nothing compared here was produced by the code being
 * tested. Byte equality against them is the whole claim: ML-KEM is only useful if a key generated
 * by this library is the same key another implementation would have generated from the same seed.
 */
internal val acvpMlKemSuite: Suite = suite("ACVP ML-KEM") {

    /**
     * `d ‖ z` in, `ek ‖ dk` out. The third assertion re-reads the encapsulation key back out of the
     * decapsulation key, which FIPS 203 requires it to contain verbatim.
     */
    test("keyGen") {
        requiringVectors {
            val label = "ML-KEM-keyGen-FIPS203"
            val tally = Tally(label)
            acvp(label) { groups ->
                for (g in groups) {
                    val name = g.meta("parameterSet")
                    val kem = Params.kemByAcvpName[name]
                    if (kem == null) {
                        Skips.note("$label: no instance for parameterSet '$name'")
                        continue
                    }
                    tally.group()
                    for (t in g.cases.capped(label)) {
                        tally.case()
                        val keys = kem.keygen(Bytes.concat(t.p.hex("d"), t.p.hex("z")))
                        Check.eq(keys.publicKey, t.er.hex("ek"), "$name tcId=${t.tcId} ek")
                        Check.eq(keys.secretKey, t.er.hex("dk"), "$name tcId=${t.tcId} dk")
                        Check.eq(
                            kem.publicKeyOf(keys.secretKey), keys.publicKey,
                            "$name tcId=${t.tcId} dk embeds ek",
                        )
                    }
                }
            }
            tally.requireNonEmpty()
        }
    }

    /**
     * Four group kinds share this suite, keyed by the group's `function`:
     *
     *  - `encapsulation` — deterministic: the message `m` is supplied, so `c` and `K` are fixed.
     *  - `decapsulation` — recovers `K`. Note that a corrupted ciphertext is *not* an error here;
     *    FIPS 203 §7.3 returns `SHAKE256(z ‖ c)` instead, and the vector's `k` is that value. A
     *    decapsulation that threw on these would fail, and so would one that returned a real secret.
     *  - `encapsulationKeyCheck` — the standard specifies no key-validation function, so the check
     *    is whether `encapsulate` accepts the key at all: its modulus test is the validation.
     *  - `decapsulationKeyCheck` — pair consistency. A decapsulation key that does not match its own
     *    embedded encapsulation key cannot recover a secret encapsulated to that key, and because
     *    decapsulation never throws, the check is that the recovered secret *differs*.
     */
    test("encapDecap") {
        requiringVectors {
            val label = "ML-KEM-encapDecap-FIPS203"
            val tally = Tally(label)
            acvp(label) { groups ->
                for (g in groups) {
                    val name = g.meta("parameterSet")
                    val kem = Params.kemByAcvpName[name]
                    if (kem == null) {
                        Skips.note("$label: no instance for parameterSet '$name'")
                        continue
                    }
                    val fn = g.meta("function")
                    if (fn !in KNOWN_FUNCTIONS) {
                        Skips.note("$label: unhandled function '$fn'")
                        continue
                    }
                    tally.group()
                    for (t in g.cases.capped("$label/$fn")) {
                        tally.case()
                        val at = "$name/$fn tcId=${t.tcId}"
                        when (fn) {
                            "encapsulation" -> {
                                val ek = t.p.hexOrNull("ek") ?: g.p.hex("ek")
                                val r = kem.encapsulate(ek, t.p.hex("m"))
                                Check.eq(r.cipherText, t.er.hex("c"), "$at c")
                                Check.eq(r.sharedSecret, t.er.hex("k"), "$at K")
                            }

                            "decapsulation" -> {
                                val dk = t.p.hexOrNull("dk") ?: g.p.hex("dk")
                                Check.eq(kem.decapsulate(t.p.hex("c"), dk), t.er.hex("k"), "$at K")
                            }

                            "encapsulationKeyCheck" -> {
                                val ek = t.p.hexOrNull("ek") ?: g.p.hex("ek")
                                val passed = try {
                                    kem.encapsulate(ek)
                                    true
                                } catch (e: Exception) {
                                    false
                                }
                                Check.eq(passed, t.ip.bool("testPassed"), "$at accepted")
                            }

                            "decapsulationKeyCheck" -> {
                                val dk = t.ip.hex("dk")
                                val ek = t.ip.hex("ek")
                                var passed = dk.size == kem.secretKeyLen
                                if (passed) {
                                    Check.eq(kem.publicKeyOf(dk), ek, "$at dk embeds ek")
                                    val enc = kem.encapsulate(ek)
                                    passed = try {
                                        Bytes.equal(kem.decapsulate(enc.cipherText, dk), enc.sharedSecret)
                                    } catch (e: Exception) {
                                        false
                                    }
                                }
                                Check.eq(passed, t.ip.bool("testPassed"), "$at consistent")
                            }
                        }
                    }
                }
            }
            tally.requireNonEmpty()
        }
    }
}

private val KNOWN_FUNCTIONS = setOf(
    "encapsulation", "decapsulation", "encapsulationKeyCheck", "decapsulationKeyCheck",
)
