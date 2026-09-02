package io.github.mortezajavadian.pq.core

import java.security.SecureRandom

/**
 * Byte-level helpers shared by both schemes.
 *
 * Deliberately small: everything here exists because a lattice scheme needs it in a *specific* form,
 * and each one is a place where a convenient-looking Kotlin idiom would silently change the wire
 * format.
 */
internal object Bytes {

    /** Empty array, shared. Used as the default signing context. */
    val EMPTY = ByteArray(0)

    private val random = SecureRandom()

    /** CSPRNG bytes. The only source of randomness in this package. */
    fun random(length: Int): ByteArray = ByteArray(length).also { random.nextBytes(it) }

    fun concat(vararg parts: ByteArray): ByteArray {
        var total = 0
        for (p in parts) total += p.size
        val out = ByteArray(total)
        var pos = 0
        for (p in parts) {
            p.copyInto(out, pos)
            pos += p.size
        }
        return out
    }

    /**
     * Length-checked equality with no early exit — the accumulate-then-compare form.
     *
     * Every caller compares something secret-adjacent: the public-key modulus round-trip, the secret
     * key's own hash, the re-encrypted ciphertext that decides ML-KEM's implicit reject, and the
     * commitment hash in signature verification. An early-exit compare would leak how far the
     * comparison got.
     */
    fun equal(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun equal(a: ByteArray, b: ByteArray, bFrom: Int, bTo: Int): Boolean {
        if (a.size != bTo - bFrom) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[bFrom + i].toInt())
        return diff == 0
    }

    /** `(1 shl bits) - 1`. */
    fun mask(bits: Int): Int = (1 shl bits) - 1

    /**
     * The ML-DSA domain prefix: `0x00 || len(ctx) || ctx || msg`.
     *
     * This is protocol-visible and not optional. The public `sign`/`verify` pair signs this
     * envelope, never the bare message, so a signature produced over the raw bytes would verify
     * nowhere. With the empty context every caller in this app uses, the prefix is the two bytes
     * `00 00`.
     */
    fun signedMessage(msg: ByteArray, ctx: ByteArray = EMPTY): ByteArray {
        if (ctx.size > 255) throw IllegalArgumentException("context should be less than 255 bytes")
        val out = ByteArray(2 + ctx.size + msg.size)
        out[0] = 0
        out[1] = ctx.size.toByte()
        ctx.copyInto(out, 2)
        msg.copyInto(out, 2 + ctx.size)
        return out
    }

    /** Zeroes the arrays. Called on seeds, noise and derived randomness once they are consumed. */
    fun clean(vararg arrays: ByteArray) {
        for (a in arrays) a.fill(0)
    }

    /**
     * Zeroes polynomials. Spread a vector into it (`cleanPolys(*vec)`) — a distinct name from
     * [clean] because on the JVM both erase to `[[I` / `[[B` and an overload pair would be
     * ambiguous at the call site for an empty vararg.
     */
    fun cleanPolys(vararg polys: IntArray) {
        for (p in polys) p.fill(0)
    }

    fun require(condition: Boolean, message: () -> String) {
        if (!condition) throw IllegalArgumentException(message())
    }

    /** Length assertion with the argument's name, matching the JS `abytes(value, len, name)` guard. */
    fun requireSize(value: ByteArray, size: Int, name: String) {
        if (value.size != size) {
            throw IllegalArgumentException("$name: expected $size bytes, got ${value.size}")
        }
    }
}
