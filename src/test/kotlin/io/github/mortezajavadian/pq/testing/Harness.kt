package io.github.mortezajavadian.pq.testing

/**
 * The test harness.
 *
 * Suites are plain data — a name and a list of named bodies — so the same suite objects are driven
 * by two front ends that cannot drift apart: [io.github.mortezajavadian.pq.PqVectorsTest], the
 * JUnit 5 `@TestFactory` that `./gradlew test` runs, and [io.github.mortezajavadian.pq.main], a bare
 * `main()` that needs nothing on the classpath but `kotlin-stdlib`. Every assertion, skip and count
 * below is shared.
 *
 * Two properties this harness enforces that a plain assertion library does not:
 *
 *  - **A case that asserted nothing fails.** A vector loop over an empty file runs zero iterations
 *    and reaches its end without complaint; the run is then green in exactly the case where it
 *    verified nothing. [Check] counts assertions and [runCase] rejects a case that made none.
 *  - **Skips are counted, named and reported.** This library does not implement every ACVP mode
 *    (no pre-hash, no external-mu, no `getPublicKey` for ML-DSA), so groups must be passed over.
 *    Passing over a group silently would overstate coverage, which for a validation suite is the
 *    one thing worse than failing.
 */
internal class Case(val name: String, val body: () -> Unit)

internal class Suite(val name: String, val cases: List<Case>)

internal class SuiteBuilder(private val name: String) {
    private val cases = ArrayList<Case>()

    fun test(name: String, body: () -> Unit) {
        cases += Case(name, body)
    }

    fun build(): Suite = Suite(name, cases)
}

internal fun suite(name: String, build: SuiteBuilder.() -> Unit): Suite =
    SuiteBuilder(name).apply(build).build()

/** Thrown to end a case as skipped rather than passed. */
internal class SkipCase(message: String) : Exception(message)

internal fun skipCase(reason: String): Nothing = throw SkipCase(reason)

/** Records a group or case passed over inside an otherwise-running test. */
internal object Skips {
    private val counts = LinkedHashMap<String, Int>()

    fun note(reason: String) {
        counts[reason] = (counts[reason] ?: 0) + 1
    }

    fun snapshot(): Map<String, Int> = LinkedHashMap(counts)

    fun clear() = counts.clear()
}

/**
 * What a case consumed, reported next to its result.
 *
 * [Tally] catches a loop that ran *zero* times; nothing catches a loop that ran a hundred times when
 * the file holds a thousand cases — a group filter that matched two of twelve groups, a `when` whose
 * cases all fell through to a skip, a wrong directory name that happened to find a smaller file. The
 * counts are therefore printed rather than merely asserted on, so the claim "every vector in the file
 * was checked" is something a reader can verify against the file instead of taking on trust.
 */
internal object Notes {
    private val lines = ArrayList<String>()

    fun add(line: String) {
        lines.add(line)
    }

    fun snapshot(): List<String> = ArrayList(lines)

    fun clear() = lines.clear()
}

internal object Check {
    var assertions: Long = 0L
        private set

    fun reset() {
        assertions = 0L
    }

    private fun bump() {
        assertions++
    }

    fun ok(condition: Boolean, message: String) {
        bump()
        if (!condition) throw AssertionError(message)
    }

    fun eq(actual: ByteArray, expected: ByteArray, message: String = "") {
        bump()
        if (actual.contentEquals(expected)) return
        throw AssertionError(
            buildString {
                if (message.isNotEmpty()) append(message).append(": ")
                append("bytes differ\n  actual   (${actual.size}) ${preview(actual)}")
                append("\n  expected (${expected.size}) ${preview(expected)}")
                val at = actual.indices.firstOrNull { i -> i >= expected.size || actual[i] != expected[i] }
                if (at != null) append("\n  first difference at byte $at")
            }
        )
    }

    fun eq(actual: Boolean, expected: Boolean, message: String = "") = eqAny(actual, expected, message)

    fun eq(actual: Int, expected: Int, message: String = "") = eqAny(actual, expected, message)

    fun eq(actual: String, expected: String, message: String = "") = eqAny(actual, expected, message)

    private fun eqAny(actual: Any?, expected: Any?, message: String) {
        bump()
        if (actual == expected) return
        val prefix = if (message.isEmpty()) "" else "$message: "
        throw AssertionError("${prefix}expected <$expected> but was <$actual>")
    }

    /** Asserts [body] throws, and hands the exception back so a caller can inspect its message. */
    fun throws(message: String = "", body: () -> Unit): Throwable {
        bump()
        try {
            body()
        } catch (e: Throwable) {
            if (e is AssertionError) throw e
            return e
        }
        val prefix = if (message.isEmpty()) "" else "$message: "
        throw AssertionError("${prefix}expected an exception, none was thrown")
    }

    /** Asserts [body] throws and that the message mentions [substring]. */
    fun throwsWith(substring: String, message: String = "", body: () -> Unit) {
        val e = throws(message, body)
        bump()
        val text = e.message ?: ""
        if (!text.contains(substring)) {
            val prefix = if (message.isEmpty()) "" else "$message: "
            throw AssertionError("${prefix}expected a message containing '$substring', got '$text'")
        }
    }

    private fun preview(b: ByteArray): String {
        val head = Hex.encode(b.copyOfRange(0, minOf(b.size, 32)))
        return if (b.size <= 32) head else "$head…"
    }
}

/**
 * Counts what a vector loop actually consumed, and refuses to let it finish empty.
 *
 * The reference suite guards its Wycheproof loader this way (`no test groups in …: vector file
 * empty or corrupt`); the same guard belongs on the ACVP loader, which has the identical failure
 * mode — a truncated archive yields zero groups and every assertion below it is never reached.
 */
internal class Tally(private val label: String) {
    var groups = 0
        private set
    var cases = 0
        private set

    fun group() {
        groups++
    }

    fun case() {
        cases++
    }

    fun requireNonEmpty() {
        if (groups == 0) throw AssertionError("no test groups in $label: vector file empty or corrupt")
        if (cases == 0) throw AssertionError("no test cases in $label: every group was empty or skipped")
        Notes.add("$label: $this")
    }

    override fun toString(): String = "$groups groups / $cases cases"
}

/** How a single case ended. [Outcome.SKIPPED] is never reported as success by either front end. */
internal enum class Outcome { PASSED, FAILED, SKIPPED }

internal class CaseResult(
    val suite: String,
    val case: String,
    val outcome: Outcome,
    val assertions: Long,
    val detail: String?,
    /** Only the skips this case added, so a per-case line does not repeat the whole run's history. */
    val skips: Map<String, Int>,
    /** What the case consumed — see [Notes]. */
    val notes: List<String>,
    val nanos: Long,
)

/**
 * Runs one case and classifies it, with the harness's central invariant applied here so both front
 * ends inherit it: **a case that finished without asserting anything is a failure, not a pass.**
 *
 * That is not a stylistic rule. Every vector-backed case in this suite is a loop over a file, and
 * the failure mode of a loop over a file is running zero iterations — a wrong directory name, an
 * archive that unpacked empty, a group filter that matched nothing. All of those reach the end of
 * the body with no exception, and reporting them green is exactly the outcome a validation suite
 * must never produce. [Tally] catches it for the loaders that have one; this catches it for
 * everything else.
 */
internal fun runCase(suite: String, case: Case): CaseResult {
    Check.reset()
    Notes.clear()
    val before = Skips.snapshot()
    val started = System.nanoTime()
    var outcome = Outcome.PASSED
    var detail: String? = null
    try {
        case.body()
    } catch (e: SkipCase) {
        outcome = Outcome.SKIPPED
        detail = e.message
    } catch (e: Throwable) {
        outcome = Outcome.FAILED
        detail = describe(e)
    }
    val nanos = System.nanoTime() - started
    val assertions = Check.assertions
    if (outcome == Outcome.PASSED && assertions == 0L) {
        outcome = Outcome.FAILED
        detail = "the case made no assertions — it verified nothing"
    }
    return CaseResult(
        suite,
        case.name,
        outcome,
        assertions,
        detail,
        added(before, Skips.snapshot()),
        Notes.snapshot(),
        nanos,
    )
}

private fun added(before: Map<String, Int>, after: Map<String, Int>): Map<String, Int> {
    val out = LinkedHashMap<String, Int>()
    for ((reason, count) in after) {
        val delta = count - (before[reason] ?: 0)
        if (delta > 0) out[reason] = delta
    }
    return out
}

private fun describe(e: Throwable): String {
    val text = e.message ?: e.toString()
    return if (e is AssertionError) text else "${e::class.java.simpleName}: $text"
}
