package io.github.mortezajavadian.pq.testing

import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.util.zip.GZIPInputStream

/**
 * Locates and streams the NIST ACVP and Wycheproof vector files.
 *
 * The vectors are not vendored — see `scripts/fetch-vectors.sh` and the pin it carries. The search
 * order is `-Dpq.vectors=…`, then `$PQ_VECTORS`, then a `test-vectors` directory found by walking up
 * from the working directory, so the suite works the same from Gradle, from an IDE and from a bare
 * `java -cp`.
 *
 * When the vectors are absent the vector-backed tests report SKIPPED rather than passing. Set
 * `PQ_REQUIRE_VECTORS=1` (CI does) to turn absence into a failure instead, because "skipped" and
 * "passed" must never look alike in a suite whose whole purpose is external agreement.
 */
internal object Vectors {
    class Missing(message: String) : Exception(message)

    val root: File? by lazy {
        val explicit = System.getProperty("pq.vectors") ?: System.getenv("PQ_VECTORS")
        if (explicit != null) return@lazy File(explicit).takeIf { it.isDirectory }
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "test-vectors")
            if (candidate.isDirectory) return@lazy candidate
            dir = dir.parentFile
        }
        null
    }

    val required: Boolean = System.getenv("PQ_REQUIRE_VECTORS") == "1"

    private fun find(vararg parts: String): File {
        val base = root ?: throw Missing(
            "no vector directory found — run ./scripts/fetch-vectors.sh (or set -Dpq.vectors=…)"
        )
        val rel = parts.joinToString("/")
        for (name in listOf("$rel.json.gz", "$rel.json")) {
            val f = File(base, name)
            if (f.isFile) return f
        }
        throw Missing("missing vector file ${base.name}/$rel.json[.gz]")
    }

    /** One of `prompt`, `expectedResults`, `internalProjection` for an ACVP suite directory. */
    fun acvp(suite: String, file: String): File = find("acvp", suite, file)

    fun wycheproof(name: String): File = find("wycheproof", "testvectors_v1", name)

    /** ACVP suite directories actually present, so the hash tests can discover their own names. */
    fun acvpSuites(): List<String> {
        val base = root ?: return emptyList()
        val dir = File(base, "acvp")
        if (!dir.isDirectory) return emptyList()
        return dir.listFiles()?.filter { it.isDirectory }?.map { it.name }?.sorted() ?: emptyList()
    }

    private fun reader(file: File): BufferedReader {
        val raw = BufferedInputStream(FileInputStream(file), 1 shl 16)
        val stream = if (file.name.endsWith(".gz")) GZIPInputStream(raw, 1 shl 16) else raw
        return BufferedReader(InputStreamReader(stream, Charsets.UTF_8), 1 shl 16)
    }

    /**
     * The file's own top-level scalars — `algorithm`, `revision`, `mode`. Read from a separate open,
     * so a suite can assert it is testing the function the file claims to hold.
     */
    fun header(file: File, before: String = "testGroups"): Obj =
        reader(file).use { Json(it).scalarsBefore(before) }

    /**
     * Streams the `testGroups` of one file. Groups arrive one at a time and are dropped again; a
     * group must be consumed before the iterator advances.
     */
    class Groups(file: File, key: String = "testGroups") : Closeable {
        private val reader: BufferedReader = reader(file)

        @Suppress("UNCHECKED_CAST")
        val iterator: Iterator<Map<String, Any?>> =
            Json(reader).arrayAt(key).map { it as Map<String, Any?> }.iterator()

        override fun close() = reader.close()
    }
}

// ---- map accessors -------------------------------------------------------------------------
//
// ACVP and Wycheproof both carry byte strings as hex and identifiers as JSON numbers. Reading them
// through named accessors rather than raw casts means a renamed or absent field fails loudly at the
// point of use instead of turning into a null that quietly compares equal to nothing.

internal typealias Obj = Map<String, Any?>

internal fun Obj.has(key: String): Boolean = containsKey(key) && this[key] != null

internal fun Obj.str(key: String): String =
    this[key] as? String ?: error("field '$key' is not a string (got ${this[key]})")

internal fun Obj.strOrNull(key: String): String? = this[key] as? String

internal fun Obj.int(key: String): Int =
    (this[key] as? Long)?.toInt() ?: error("field '$key' is not an integer (got ${this[key]})")

internal fun Obj.bool(key: String): Boolean =
    this[key] as? Boolean ?: error("field '$key' is not a boolean (got ${this[key]})")

internal fun Obj.boolOr(key: String, fallback: Boolean): Boolean = this[key] as? Boolean ?: fallback

@Suppress("UNCHECKED_CAST")
internal fun Obj.objects(key: String): List<Obj> =
    (this[key] as? List<Any?>)?.map { it as Obj } ?: error("field '$key' is not an array")

@Suppress("UNCHECKED_CAST")
internal fun Obj.strings(key: String): List<String> =
    (this[key] as? List<Any?>)?.map { it as String } ?: emptyList()

/** Hex → bytes. Empty string is a legitimate zero-length value in both vector formats. */
internal fun Obj.hex(key: String): ByteArray = Hex.decode(str(key))

internal fun Obj.hexOrNull(key: String): ByteArray? = strOrNull(key)?.let { Hex.decode(it) }

internal object Hex {
    fun decode(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd-length hex string (${s.length} chars)" }
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(s[i * 2], 16)
            val lo = Character.digit(s[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "non-hex character at offset ${i * 2} of '$s'" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun encode(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            sb.append(DIGITS[(x.toInt() shr 4) and 0xf])
            sb.append(DIGITS[x.toInt() and 0xf])
        }
        return sb.toString()
    }

    private const val DIGITS = "0123456789abcdef"
}
