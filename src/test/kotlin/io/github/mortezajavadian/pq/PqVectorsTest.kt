package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.testing.Outcome
import io.github.mortezajavadian.pq.testing.runCase
import org.junit.jupiter.api.DynamicContainer
import org.junit.jupiter.api.DynamicNode
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.opentest4j.TestAbortedException

/**
 * The JUnit 5 front end: one container per suite, one dynamic test per case.
 *
 * It contains no assertions of its own on purpose. Everything is in [ALL_SUITES] and
 * [runCase], so `./gradlew test` and the bare `main()` runner cannot disagree about what passed —
 * including the rule that a case which asserted nothing fails, and the mapping of a missing vector
 * file to *aborted* rather than *passed*. `TestAbortedException` is what makes Gradle print SKIPPED;
 * an `Assumptions.assumeTrue` would do the same, but this way the reason travels with it.
 */
class PqVectorsTest {
    @TestFactory
    fun suites(): List<DynamicNode> = ALL_SUITES.map { suite ->
        DynamicContainer.dynamicContainer(
            suite.name,
            suite.cases.map { case ->
                DynamicTest.dynamicTest(case.name) {
                    val result = runCase(suite.name, case)
                    // showStandardStreams = true in build.gradle.kts, so these reach the Gradle log:
                    // how many groups and cases each vector file actually yielded.
                    for (line in result.notes) println("consumed $line")
                    when (result.outcome) {
                        Outcome.PASSED -> Unit
                        Outcome.SKIPPED -> throw TestAbortedException(result.detail ?: "vectors missing")
                        Outcome.FAILED -> throw AssertionError(result.detail ?: "failed")
                    }
                }
            },
        )
    }
}
