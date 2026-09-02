package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.testing.Check
import io.github.mortezajavadian.pq.testing.Obj
import io.github.mortezajavadian.pq.testing.Skips
import io.github.mortezajavadian.pq.testing.Suite
import io.github.mortezajavadian.pq.testing.Tally
import io.github.mortezajavadian.pq.testing.capped
import io.github.mortezajavadian.pq.testing.eachGroupCase
import io.github.mortezajavadian.pq.testing.has
import io.github.mortezajavadian.pq.testing.hasFlag
import io.github.mortezajavadian.pq.testing.hex
import io.github.mortezajavadian.pq.testing.hexOrNull
import io.github.mortezajavadian.pq.testing.int
import io.github.mortezajavadian.pq.testing.isValid
import io.github.mortezajavadian.pq.testing.objects
import io.github.mortezajavadian.pq.testing.requiringVectors
import io.github.mortezajavadian.pq.testing.str
import io.github.mortezajavadian.pq.testing.strOrNull
import io.github.mortezajavadian.pq.testing.suite
import io.github.mortezajavadian.pq.testing.wycheproof

/**
 * ML-DSA against Project Wycheproof.
 *
 * Where ACVP's sigVer suite corrupts signatures systematically, Wycheproof's negative cases are
 * hand-aimed at implementation mistakes: a hint that decodes to more positions than ω allows, a
 * response at exactly the norm bound, a context byte counted wrongly, an expanded signing key whose
 * `s1`/`s2` coefficients sit outside `[−η, η]`. Each is a real bug some implementation shipped.
 *
 * Two things are passed over and counted. Cases flagged `Internal` sign a caller-supplied μ, which
 * this library does not expose; so does every `mu`-only case in the expanded-key file. Both are the
 * same missing feature — external-μ — reported separately because they come from different files.
 */
internal val wycheproofMlDsaSuite: Suite = suite("Wycheproof ML-DSA") {

    for ((level, dsa) in Params.dsaLevels) {

        test("ML-DSA-$level verify") {
            requiringVectors {
                eachGroupCase("mldsa_${level}_verify_test") { g, t, at ->
                    val pk = g.hex("publicKey")
                    // A malformed signature must be rejected, not raise: the signature is the
                    // attacker-controlled input, so `verify` returning false and `verify` throwing
                    // are the same verdict to a caller that wrote try/catch — and different to one
                    // that did not.
                    val valid = try {
                        dsa.verify(t.hex("sig"), t.hex("msg"), pk, t.hexOrNull("ctx") ?: ByteArray(0))
                    } catch (e: Exception) {
                        false
                    }
                    Check.eq(valid, t.isValid(), "$at verdict")
                }
            }
        }

        /**
         * Signing from a 32-byte seed. The group's own `publicKey` is checked against the key the
         * seed derives, so a wrong keygen fails here before any signature is compared.
         *
         * Hedged cases carry the `Randomized` flag: their signature is not reproducible, so the
         * assertion becomes that this library's verifier accepts a third party's signature — which
         * is the interoperability direction the deterministic comparison cannot test.
         */
        test("ML-DSA-$level sign (from seed)") {
            requiringVectors {
                val name = "mldsa_${level}_sign_seed_test"
                val tally = Tally(name)
                wycheproof(name) { groups ->
                    for (g in groups) {
                        tally.group()
                        val cases = g.objects("tests").capped(name)
                        val keys = try {
                            dsa.keygen(g.hex("privateSeed"))
                        } catch (e: Exception) {
                            // An unusable seed makes every case in the group an invalid one.
                            for (t in cases) {
                                tally.case()
                                Check.eq(t.str("result"), "invalid", "${label(name, t)} rejected seed")
                            }
                            continue
                        }
                        Check.eq(keys.publicKey, g.hex("publicKey"), "$name group pk")
                        for (t in cases) {
                            tally.case()
                            val at = label(name, t)
                            if (t.hasFlag("Internal")) {
                                Skips.note("$name: external-mu signing is not implemented")
                                continue
                            }
                            val ctx = t.hexOrNull("ctx") ?: ByteArray(0)
                            if (!t.isValid()) {
                                Check.throws(at) { dsa.sign(t.hex("msg"), keys.secretKey, ctx, DETERMINISTIC) }
                            } else if (t.hasFlag("Randomized")) {
                                Check.ok(
                                    dsa.verify(t.hex("sig"), t.hex("msg"), keys.publicKey, ctx),
                                    "$at hedged signature should verify",
                                )
                            } else {
                                val sig = dsa.sign(t.hex("msg"), keys.secretKey, ctx, DETERMINISTIC)
                                Check.eq(sig, t.hex("sig"), "$at signature")
                            }
                        }
                    }
                }
                tally.requireNonEmpty()
            }
        }

        /**
         * Signing from an expanded secret key — the form `sign` takes, and the form a key from
         * another implementation arrives in. The malformed-key cases here are the only coverage of a
         * third party's bad expanded key, and they are caught on decode: a `s1`/`s2` coefficient
         * outside `[−η, η]` fits the packed field but is not a valid key, and a signer that accepted
         * it would produce a signature over the wrong secret rather than fail.
         */
        test("ML-DSA-$level sign (expanded key)") {
            requiringVectors {
                val name = "mldsa_${level}_sign_noseed_test"
                eachGroupCase(name) { g, t, at ->
                    val sk = g.hex("privateKey")
                    val rnd = t.hexOrNull("rnd") ?: DETERMINISTIC
                    val ctx = t.hexOrNull("ctx") ?: ByteArray(0)
                    if (t.isValid()) {
                        if (t.has("msg")) {
                            Check.eq(dsa.sign(t.hex("msg"), sk, ctx, rnd), t.hex("sig"), "$at signature")
                        }
                        if (t.has("mu")) {
                            Skips.note("$name: external-mu signing is not implemented")
                        }
                        if (!t.has("msg") && !t.has("mu")) {
                            Skips.note("$name: valid case carries neither msg nor mu")
                        }
                    } else if (t.has("mu") && !t.has("msg")) {
                        Skips.note("$name: external-mu signing is not implemented")
                    } else {
                        Check.throws(at) { dsa.sign(t.hexOrNull("msg") ?: ByteArray(0), sk, ctx, rnd) }
                    }
                }
            }
        }
    }
}

/**
 * FIPS 204's deterministic variant: `rnd` is 32 zero bytes, not "no randomness".
 *
 * The library's `extraEntropy = null` default draws fresh entropy and produces a hedged signature
 * that is valid but does not match any vector, so every deterministic comparison must pass the zeros
 * explicitly. This is the single most likely way to get a green-looking suite that tests nothing.
 */
private val DETERMINISTIC = ByteArray(32)

private fun label(name: String, t: Obj): String {
    val comment = t.strOrNull("comment").orEmpty()
    return "$name tcId=${t.int("tcId")}" + if (comment.isEmpty()) "" else " ($comment)"
}
