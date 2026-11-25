package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.rewrite.RewriteManager
import net.portswigger.mcp.rewrite.RewritePanel
import net.portswigger.mcp.rewrite.RewriteProxyHandler
import net.portswigger.mcp.rewrite.ResponseProxyHandler
import net.portswigger.mcp.rewrite.proxyPreservesResponseEncoding

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val rewriteManager = RewriteManager(api.persistence().extensionData()) {
            proxyPreservesResponseEncoding(api.burpSuite().exportProjectOptionsAsJson())
        }
        val serverManager = KtorServerManager(api, rewriteManager)
        val rewriteRegistration = api.proxy().registerRequestHandler(RewriteProxyHandler(rewriteManager))
        val responseRegistration = api.proxy().registerResponseHandler(ResponseProxyHandler(rewriteManager))

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)
        api.userInterface().registerSuiteTab("MCP Rewrite", RewritePanel(rewriteManager))

        api.extension().registerUnloadingHandler {
            rewriteManager.disableAll()
            rewriteRegistration.deregister()
            responseRegistration.deregister()
            serverManager.shutdown()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }
}
