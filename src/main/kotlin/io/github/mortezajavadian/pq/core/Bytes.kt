package io.github.mortezajavadian.pq.core

import java.security.SecureRandom

/**
 * Byte-level helpers shared by both schemes.
 *
 * Deliberately small: everything here exists because a lattice scheme needs it in a *specific* form,
 * and each one is a place where a convenient-looking Kotlin idiom would silently change the wire
 * format.
 *
 * Three members are API — [EMPTY], [equal] and [clean] — because a caller of the schemes needs
 * exactly those three: the value the default signing context has, a comparison that does not stop at
 * the first differing byte, and the wipe this library performs on its own copies. They are also the
 * three noble-post-quantum exports from its `utils` that are pure functions over arrays the caller
 * already owns.
 *
 * noble's `randomBytes` is the one export deliberately *not* mirrored. [random] below keeps its
 * [SecureRandom] private and stays internal: a caller who needs entropy has `SecureRandom` in the
 * platform, so publishing a wrapper would add a randomness seam — one observation and substitution
 * point for every seed and every `rnd` this library draws — and buy nothing. Everything else here is
 * a wire-format or bounds detail with no meaning outside the package.
 */
public object Bytes {

    /** Empty array, shared. Used as the default signing context. */
    public val EMPTY: ByteArray = ByteArray(0)

    private val random = SecureRandom()

    /** CSPRNG bytes. The only source of randomness in this package. */
    internal fun random(length: Int): ByteArray = ByteArray(length).also { random.nextBytes(it) }

    internal fun concat(vararg parts: ByteArray): ByteArray {
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
     * Every caller inside this library compares something secret-adjacent: the public-key modulus
     * round-trip, the secret key's own hash, the re-encrypted ciphertext that decides ML-KEM's
     * implicit reject, and the commitment hash in signature verification. An early-exit compare would
     * leak how far the comparison got.
     *
     * Reading every byte is a property of the source, not a guarantee about the machine: this is
     * *not* certified constant-time. Unequal lengths still return immediately, and on the JVM the
     * JIT, bounds-check elimination and the GC all vary with things this loop does not control. Use
     * it because it is the right shape, not because it makes timing unobservable.
     */
    public fun equal(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    internal fun equal(a: ByteArray, b: ByteArray, bFrom: Int, bTo: Int): Boolean {
        if (a.size != bTo - bFrom) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[bFrom + i].toInt())
        return diff == 0
    }

    /** `(1 shl bits) - 1`. Callers pass 1..31; `mask(32)` is 0, since Kotlin's `shl` counts mod 32. */
    internal fun mask(bits: Int): Int = (1 shl bits) - 1

    /**
     * The ML-DSA domain prefix: `0x00 || len(ctx) || ctx || msg`.
     *
     * This is protocol-visible and not optional. The public `sign`/`verify` pair signs this
     * envelope, never the bare message, so a signature produced over the raw bytes would verify
     * nowhere. With the empty context every caller in this app uses, the prefix is the two bytes
     * `00 00`.
     */
    internal fun signedMessage(msg: ByteArray, ctx: ByteArray = EMPTY): ByteArray {
        if (ctx.size > 255) throw IllegalArgumentException("context should be less than 255 bytes")
        val out = ByteArray(2 + ctx.size + msg.size)
        out[0] = 0
        out[1] = ctx.size.toByte()
        ctx.copyInto(out, 2)
        msg.copyInto(out, 2 + ctx.size)
        return out
    }

    /**
     * Zeroes the arrays. Called on seeds, noise and derived randomness once they are consumed.
     *
     * API because a caller holding a secret key or a shared secret needs the same wipe this library
     * performs on its own copies, and the wipe has to be `fill(0)` rather than dropping the reference.
     * Best-effort on the JVM: a moving collector may already have copied the array elsewhere, and a
     * release build with R8 in full mode may dead-store-eliminate the fill on an array it can prove is
     * unread afterwards. It clears the copy you handed it; it cannot clear copies it never saw.
     */
    public fun clean(vararg arrays: ByteArray) {
        for (a in arrays) a.fill(0)
    }

    /**
     * Zeroes polynomials. Spread a vector into it (`cleanPolys(*vec)`) — a distinct name from
     * [clean] because on the JVM both erase to `[[I` / `[[B` and an overload pair would be
     * ambiguous at the call site for an empty vararg.
     */
    internal fun cleanPolys(vararg polys: IntArray) {
        for (p in polys) p.fill(0)
    }

    /**
     * Guard with a lazily built message.
     *
     * Internal, and staying that way: the name collides with `kotlin.require`, so a public one would
     * mean a caller inside `with(Bytes) { … }` silently resolving to this overload — same shape, but
     * `IllegalArgumentException` from a different line and no `contract` telling the compiler the
     * condition held.
     */
    internal fun require(condition: Boolean, message: () -> String) {
        if (!condition) throw IllegalArgumentException(message())
    }

    /** Length assertion with the argument's name, matching the JS `abytes(value, len, name)` guard. */
    internal fun requireSize(value: ByteArray, size: Int, name: String) {
        if (value.size != size) {
            throw IllegalArgumentException("$name: expected $size bytes, got ${value.size}")
        }
    }
}
