import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.0.21"
    `java-library`
}

group = "io.github.mortezajavadian"
version = "0.1.0-SNAPSHOT"

dependencies {
    // kotlin("test") follows the plugin's version and resolves to the JUnit 5 flavour once
    // useJUnitPlatform() is on, so no JUnit coordinate has to be pinned here by hand.
    testImplementation(kotlin("test"))
}

kotlin {
    // Built with a modern JDK, but emitting Java 8 bytecode: the schemes use nothing newer than
    // BigInteger and SecureRandom, and 1.8 is the one target every Android and JVM consumer accepts.
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
    // The ACVP suites are long-running and worth watching; a silent test task hides which of them
    // actually ran, and a validation run that cannot be seen is not a validation run.
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
