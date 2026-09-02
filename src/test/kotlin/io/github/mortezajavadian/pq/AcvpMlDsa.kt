package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.testing.AcvpGroup
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
 * ML-DSA against NIST's ACVP vectors — `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204` and
 * `ML-DSA-sigVer-FIPS204`, all three parameter sets.
 *
 * A signature scheme cannot be validated by using it: a subtly wrong implementation still returns
 * `true` for signatures it produced itself. So `sigGen` compares signature bytes to NIST's, and
 * `sigVer` compares an accept/reject decision to NIST's, including on the deliberately corrupted
 * cases where the only correct answer is `false`.
 *
 * Three ACVP group kinds are passed over because the library does not implement them, and each one
 * is counted and named in the summary rather than quietly stepped around:
 *
 *  - **pre-hash (HashML-DSA)** — the FIPS 204 §5.4 variant that signs `H(M)` under an OID prefix.
 *  - **external-μ** — signing a caller-computed μ, for the split "hash on one machine, sign on
 *    another" deployment.
 *  - **`getPublicKey(sk)`** — recovering a verification key from a signing key. FIPS 204 does not
 *    store `t1` in the signing key, so this means recomputing `A·s1 + s2` and rounding; the
 *    reference implementation offers it and this library does not.
 */
internal val acvpMlDsaSuite: Suite = suite("ACVP ML-DSA") {

    test("keyGen") {
        requiringVectors {
            val label = "ML-DSA-keyGen-FIPS204"
            val tally = Tally(label)
            acvp(label) { groups ->
                for (g in groups) {
                    val name = g.meta("parameterSet")
                    val dsa = Params.dsaByAcvpName[name]
                    if (dsa == null) {
                        Skips.note("$label: no instance for parameterSet '$name'")
                        continue
                    }
                    Skips.note("$label: getPublicKey(sk) not implemented — pk is checked against the vector only")
                    tally.group()
                    for (t in g.cases.capped(label)) {
                        tally.case()
                        val keys = dsa.keygen(t.p.hex("seed"))
                        Check.eq(keys.publicKey, t.er.hex("pk"), "$name tcId=${t.tcId} pk")
                        Check.eq(keys.secretKey, t.er.hex("sk"), "$name tcId=${t.tcId} sk")
                    }
                }
            }
            tally.requireNonEmpty()
        }
    }

    /**
     * Signature bytes, compared to NIST's.
     *
     * `rnd` is FIPS 204's per-signature randomness: absent means the deterministic variant, which is
     * 32 zero bytes and not "no randomness" — a signer that substituted fresh entropy there would
     * produce a valid signature that does not match the vector, which is exactly the mistake these
     * groups catch.
     */
    test("sigGen") {
        requiringVectors {
            val label = "ML-DSA-sigGen-FIPS204"
            val tally = Tally(label)
            acvp(label) { groups ->
                for (g in groups) {
                    val name = g.meta("parameterSet")
                    val dsa = Params.dsaByAcvpName[name]
                    if (dsa == null) {
                        Skips.note("$label: no instance for parameterSet '$name'")
                        continue
                    }
                    val mode = g.mode()
                    if (mode.unsupported != null) {
                        Skips.note("$label: ${mode.unsupported}")
                        continue
                    }
                    tally.group()
                    for (t in g.cases.capped("$label/${mode.describe}")) {
                        tally.case()
                        val at = "$name/${mode.describe} tcId=${t.tcId}"
                        val sk = t.p.hexOrNull("sk") ?: g.p.hex("sk")
                        val rnd = t.p.hexOrNull("rnd") ?: ByteArray(32)
                        val sig = if (mode.internal) {
                            dsa.signInternal(t.p.hex("message"), sk, rnd)
                        } else {
                            val ctx = t.p.hexOrNull("context") ?: ByteArray(0)
                            dsa.sign(t.p.hex("message"), sk, ctx, rnd)
                        }
                        Check.eq(sig, t.er.hex("signature"), "$at signature")
                    }
                }
            }
            tally.requireNonEmpty()
        }
    }

    /** Accept/reject decisions, compared to NIST's — including every case whose answer is `false`. */
    test("sigVer") {
        requiringVectors {
            val label = "ML-DSA-sigVer-FIPS204"
            val tally = Tally(label)
            acvp(label) { groups ->
                for (g in groups) {
                    val name = g.meta("parameterSet")
                    val dsa = Params.dsaByAcvpName[name]
                    if (dsa == null) {
                        Skips.note("$label: no instance for parameterSet '$name'")
                        continue
                    }
                    val mode = g.mode()
                    if (mode.unsupported != null) {
                        Skips.note("$label: ${mode.unsupported}")
                        continue
                    }
                    tally.group()
                    for (t in g.cases.capped("$label/${mode.describe}")) {
                        tally.case()
                        val at = "$name/${mode.describe} tcId=${t.tcId}"
                        val pk = t.p.hexOrNull("pk") ?: g.p.hex("pk")
                        val sig = t.p.hex("signature")
                        val msg = t.p.hex("message")
                        val valid = if (mode.internal) {
                            dsa.verifyInternal(sig, msg, pk)
                        } else {
                            dsa.verify(sig, msg, pk, t.p.hexOrNull("context") ?: ByteArray(0))
                        }
                        Check.eq(valid, t.er.bool("testPassed"), "$at verdict")
                    }
                }
            }
            tally.requireNonEmpty()
        }
    }
}

/** What an ML-DSA sigGen/sigVer group asks for, and whether this library can answer it. */
private class DsaMode(val internal: Boolean, val describe: String, val unsupported: String?)

private fun AcvpGroup.mode(): DsaMode {
    val iface = metaOrNull("signatureInterface") ?: "external"
    val preHash = metaOrNull("preHash") == "preHash"
    val externalMu = p["externalMu"] as? Boolean ?: false
    val describe = buildString {
        append(iface)
        if (externalMu) append("+externalMu")
        if (preHash) append("+preHash")
    }
    val unsupported = when {
        externalMu -> "external-mu signing is not implemented ($describe)"
        preHash -> "HashML-DSA pre-hash is not implemented ($describe)"
        iface != "internal" && iface != "external" -> "unknown signatureInterface '$iface'"
        else -> null
    }
    return DsaMode(internal = iface == "internal", describe = describe, unsupported = unsupported)
}
