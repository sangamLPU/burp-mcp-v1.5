import java.time.Instant
import org.gradle.api.tasks.bundling.AbstractArchiveTask
import org.gradle.api.tasks.testing.Test

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    java
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()
description = providers.gradleProperty("description").get()

// Keep development outputs separate from the preserved v1.4.0 release artifacts.
if (providers.gradleProperty("developmentBuild").orNull == "true") {
    layout.buildDirectory.set(layout.projectDirectory.dir("build/dev-v1.5.0"))
}

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
}

val extensionBuildId = providers.gradleProperty("build.id").get()
val extensionVersion = project.version.toString()

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }

    compilerOptions {
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_4)
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_4)
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict"
        )
    }
}

val packagedExtensionJar = tasks.named<AbstractArchiveTask>("shadowJar")

application {
    mainClass.set("net.portswigger.mcp.ExtensionBase")
}

tasks {
    test {
        useJUnitPlatform {
            if (providers.gradleProperty("validation.mode").orElse("all").get().equals("offline", ignoreCase = true)) {
                excludeTags("loopback")
            }
        }
        systemProperty("file.encoding", "UTF-8")

        testLogging {
            events("passed", "skipped", "failed")
            showExceptions = true
            showCauses = true
            showStackTraces = true
        }
    }

    jar {
        enabled = false
    }

    shadowJar {
        archiveClassifier.set("")
        if (providers.gradleProperty("developmentBuild").orNull == "true") {
            archiveFileName.set("burp-mcp-${project.version}-all.jar")
        }
        mergeServiceFiles()

        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version,
                    "Build-Id" to extensionBuildId,
                    "Implementation-Vendor" to "PortSwigger",
                    "Built-By" to System.getProperty("user.name"),
                    "Built-Date" to Instant.now().toString(),
                    "Built-JDK" to "${System.getProperty("java.version")} (${System.getProperty("java.vendor")} ${
                        System.getProperty("java.vm.version")
                    })",
                    "Created-By" to "Gradle ${gradle.gradleVersion}"
                )
            )
        }


        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
        exclude("META-INF/INDEX.LIST")
        exclude("META-INF/DEPENDENCIES")
        exclude("META-INF/NOTICE*")
        exclude("META-INF/LICENSE*")
        exclude("module-info.class")

        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

    build {
        dependsOn(shadowJar)
    }

    withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

tasks.named<Test>("test") {
    dependsOn(packagedExtensionJar)
    systemProperty("burp.mcp.expectedVersion", extensionVersion)
    systemProperty("burp.mcp.expectedBuildId", extensionBuildId)
    systemProperty("burp.mcp.packagedJar", packagedExtensionJar.get().archiveFile.get().asFile.absolutePath)
}

tasks.wrapper {
    gradleVersion = "9.2.0"
    distributionType = Wrapper.DistributionType.BIN
}
