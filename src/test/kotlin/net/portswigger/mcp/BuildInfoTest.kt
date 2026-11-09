package net.portswigger.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.net.URLClassLoader
import java.util.jar.JarFile
import java.util.jar.Manifest

class BuildInfoTest {
    @Test
    fun `runtime identity is compiled from project metadata`() {
        val expectedVersion = System.getProperty("burp.mcp.expectedVersion")
        val expectedBuildId = System.getProperty("burp.mcp.expectedBuildId")

        assertNotNull(expectedVersion)
        assertNotNull(expectedBuildId)
        assertEquals(expectedVersion, BuildInfo.version)
        assertEquals(expectedBuildId, BuildInfo.buildId)
        assertEquals("$expectedVersion+$expectedBuildId", BuildInfo.serverVersion)
        assertFalse(BuildInfo.version == "26891" || BuildInfo.buildId == "unpackaged")
    }

    @Test
    fun `packaged extension jar manifest matches runtime identity`() {
        val jarPath = System.getProperty("burp.mcp.packagedJar")
        assertNotNull(jarPath)
        val jar = File(jarPath!!)
        assertTrue(jar.isFile, "Expected packaged extension JAR at $jarPath")

        JarFile(jar).use { packagedJar ->
            val manifest = packagedJar.manifest
            assertNotNull(manifest, "Packaged extension JAR must contain META-INF/MANIFEST.MF")
            assertTrue(BuildInfo.matchesManifest(manifest))
            assertEquals(BuildInfo.version, manifest!!.mainAttributes.getValue("Implementation-Version"))
            assertEquals(BuildInfo.buildId, manifest.mainAttributes.getValue("Build-Id"))
            assertNotNull(packagedJar.getJarEntry("net/portswigger/mcp/BuildInfo.class"))
        }

        URLClassLoader(arrayOf(jar.toURI().toURL()), ClassLoader.getPlatformClassLoader()).use { loader ->
            val packagedBuildInfo = loader.loadClass("net.portswigger.mcp.BuildInfo")
            assertEquals(BuildInfo.version, packagedBuildInfo.getField("version").get(null))
            assertEquals(BuildInfo.buildId, packagedBuildInfo.getField("buildId").get(null))
            assertEquals(BuildInfo.serverVersion, packagedBuildInfo.getField("serverVersion").get(null))
        }
    }

    @Test
    fun `missing or incorrect manifests are rejected without changing runtime identity`() {
        val runtimeVersion = BuildInfo.version
        val runtimeBuildId = BuildInfo.buildId
        val missingManifest = Manifest()
        val incorrectManifest = Manifest().apply {
            mainAttributes.putValue("Manifest-Version", "1.0")
            mainAttributes.putValue("Implementation-Version", "26891")
            mainAttributes.putValue("Build-Id", "unpackaged")
        }

        assertFalse(BuildInfo.matchesManifest(null))
        assertFalse(BuildInfo.matchesManifest(missingManifest))
        assertFalse(BuildInfo.matchesManifest(incorrectManifest))
        assertEquals(runtimeVersion, BuildInfo.version)
        assertEquals(runtimeBuildId, BuildInfo.buildId)
    }
}
