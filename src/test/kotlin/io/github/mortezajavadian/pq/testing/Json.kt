package io.github.mortezajavadian.pq.testing

import java.io.Reader

/**
 * A minimal, streaming JSON reader.
 *
 * The suite needs exactly one thing the JDK does not ship: a way to walk a multi-hundred-megabyte
 * ACVP file without holding it in memory. `ML-DSA-sigGen-FIPS204/prompt.json` is a single JSON
 * object whose `testGroups` array is the whole file; materialising that as a `Map` tree costs more
 * than a gigabyte of heap, so the reader pulls one test group at a time and drops it again — the
 * same shape as the reference implementation's `jsonGZGroups`.
 *
 * Writing a parser rather than taking a dependency also keeps `./gradlew test` runnable with
 * nothing on the test classpath but the JUnit engine, which matters for a library whose whole
 * claim is that it has no dependencies.
 *
 * A parser under a vector suite is itself load-bearing: one that silently mis-reads a hex string
 * turns a real mismatch into a green run. [jsonSelfTestSuite] is not optional decoration.
 */
internal class Json(private val src: Reader) {
    /** One character of pushback. -2 means the slot is empty; -1 is a real EOF from [Reader.read]. */
    private var pushed: Int = EMPTY

    private fun next(): Int {
        if (pushed != EMPTY) {
            val c = pushed
            pushed = EMPTY
            return c
        }
        return src.read()
    }

    private fun back(c: Int) {
        pushed = c
    }

    private fun fail(msg: String): Nothing = throw IllegalStateException("JSON: $msg")

    /** Advances past whitespace and returns the first significant character. */
    private fun skipWs(): Int {
        while (true) {
            val c = next()
            if (c == -1 || c > ' '.code) return c
        }
    }

    private fun expect(want: Char) {
        val c = skipWs()
        if (c != want.code) fail("expected '$want', got ${describe(c)}")
    }

    private fun describe(c: Int): String =
        if (c == -1) "end of input" else "'${c.toChar()}'"

    /** Reads the next complete value: Map, List, String, Long, Double, Boolean or null. */
    fun readValue(): Any? {
        val c = skipWs()
        return when {
            c == -1 -> fail("unexpected end of input")
            c == '{'.code -> readObject()
            c == '['.code -> readArray()
            c == '"'.code -> readString()
            c == 't'.code -> { readLiteral("rue"); true }
            c == 'f'.code -> { readLiteral("alse"); false }
            c == 'n'.code -> { readLiteral("ull"); null }
            else -> { back(c); readNumber() }
        }
    }

    private fun readLiteral(rest: String) {
        for (ch in rest) {
            val c = next()
            if (c != ch.code) fail("bad literal, expected '$ch', got ${describe(c)}")
        }
    }

    private fun readObject(): MutableMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        var c = skipWs()
        if (c == '}'.code) return out
        while (true) {
            if (c != '"'.code) fail("expected a key, got ${describe(c)}")
            val key = readString()
            expect(':')
            out[key] = readValue()
            c = skipWs()
            when (c) {
                ','.code -> c = skipWs()
                '}'.code -> return out
                else -> fail("expected ',' or '}', got ${describe(c)}")
            }
        }
    }

    private fun readArray(): MutableList<Any?> {
        val out = ArrayList<Any?>()
        var c = skipWs()
        if (c == ']'.code) return out
        back(c)
        while (true) {
            out.add(readValue())
            c = skipWs()
            when (c) {
                ','.code -> {}
                ']'.code -> return out
                else -> fail("expected ',' or ']', got ${describe(c)}")
            }
        }
    }

    private fun readString(): String {
        val sb = StringBuilder()
        while (true) {
            val c = next()
            when {
                c == -1 -> fail("unterminated string")
                c == '"'.code -> return sb.toString()
                c == '\\'.code -> sb.append(readEscape())
                else -> sb.append(c.toChar())
            }
        }
    }

    private fun readEscape(): Char {
        val c = next()
        return when (c) {
            '"'.code -> '"'
            '\\'.code -> '\\'
            '/'.code -> '/'
            'b'.code -> '\b'
            'f'.code -> '\u000C'
            'n'.code -> '\n'
            'r'.code -> '\r'
            't'.code -> '\t'
            'u'.code -> {
                var v = 0
                for (i in 0 until 4) {
                    val h = next()
                    val d = Character.digit(h, 16)
                    if (d < 0) fail("bad \\u escape at ${describe(h)}")
                    v = (v shl 4) or d
                }
                v.toChar()
            }
            else -> fail("bad escape ${describe(c)}")
        }
    }

    /**
     * Integral values come back as [Long] so `tcId` and `tgId` compare and print as integers.
     * Anything with a fraction or exponent becomes [Double]; no ACVP or Wycheproof field needs it,
     * but silently truncating one would be worse than carrying it.
     */
    private fun readNumber(): Any {
        val sb = StringBuilder()
        var integral = true
        while (true) {
            val c = next()
            if (c == -1) break
            val ch = c.toChar()
            if (ch in "-+0123456789") {
                sb.append(ch)
            } else if (ch == '.' || ch == 'e' || ch == 'E') {
                integral = false
                sb.append(ch)
            } else {
                back(c)
                break
            }
        }
        if (sb.isEmpty()) fail("expected a number")
        val text = sb.toString()
        return if (integral) text.toLongOrNull() ?: text.toDouble() else text.toDouble()
    }

    /**
     * Yields the elements of the top-level array at [key], one at a time, without reading the rest
     * of the document. Values under other keys are skipped without being built.
     *
     * ACVP files put `testGroups` last, after `vsId`/`algorithm`/`revision`, so the skipping is
     * cheap; Wycheproof puts a large `notes` object before `testGroups`, which is exactly the case
     * this avoids materialising.
     */
    fun arrayAt(key: String): Sequence<Any?> {
        expect('{')
        var c = skipWs()
        if (c == '}'.code) fail("no '$key' in document")
        while (true) {
            if (c != '"'.code) fail("expected a key, got ${describe(c)}")
            val k = readString()
            expect(':')
            if (k == key) return arrayElements()
            skipValue()
            c = skipWs()
            when (c) {
                ','.code -> c = skipWs()
                '}'.code -> fail("no '$key' in document")
                else -> fail("expected ',' or '}', got ${describe(c)}")
            }
        }
    }

    /**
     * The top-level scalar fields appearing before [key], with nested values skipped.
     *
     * Read from a second open of the same file, this is how a hash test confirms that
     * `acvp/SHA3-256-2.0` really does say `"algorithm": "SHA3-256"` before hashing anything with a
     * 136-byte rate. Without it, a mistyped rate in the test's own parameter table would look like a
     * library bug, and a renamed suite directory would look like a passing test of the wrong function.
     */
    fun scalarsBefore(key: String): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        expect('{')
        var c = skipWs()
        if (c == '}'.code) return out
        while (true) {
            if (c != '"'.code) fail("expected a key, got ${describe(c)}")
            val k = readString()
            expect(':')
            if (k == key) return out
            val v = skipWs()
            if (v == '{'.code || v == '['.code) skipNested(v) else { back(v); out[k] = readValue() }
            c = skipWs()
            when (c) {
                ','.code -> c = skipWs()
                '}'.code -> return out
                else -> fail("expected ',' or '}', got ${describe(c)}")
            }
        }
    }

    private fun arrayElements(): Sequence<Any?> = sequence {
        expect('[')
        var c = skipWs()
        if (c == ']'.code) return@sequence
        back(c)
        while (true) {
            yield(readValue())
            c = skipWs()
            when (c) {
                ','.code -> {}
                ']'.code -> return@sequence
                else -> fail("expected ',' or ']', got ${describe(c)}")
            }
        }
    }

    /** Consumes one value without building it. */
    private fun skipValue() {
        val c = skipWs()
        when {
            c == -1 -> fail("unexpected end of input")
            c == '{'.code || c == '['.code -> skipNested(c)
            c == '"'.code -> skipString()
            else -> { back(c); readValue() }
        }
    }

    private fun skipNested(open: Int) {
        var depth = 1
        while (depth > 0) {
            val c = next()
            when {
                c == -1 -> fail("unterminated ${describe(open)}")
                c == '"'.code -> skipString()
                c == '{'.code || c == '['.code -> depth++
                c == '}'.code || c == ']'.code -> depth--
            }
        }
    }

    private fun skipString() {
        while (true) {
            val c = next()
            when {
                c == -1 -> fail("unterminated string")
                c == '\\'.code -> next()
                c == '"'.code -> return
            }
        }
    }

    private companion object {
        const val EMPTY = -2
    }
}
