package net.portswigger.mcp.intercept

/** PowerShell commands for the local fixture. The secure-prompt variant keeps IDs out of history. */
internal object LocalTestPowerShellCommands {
    private const val PROJECT_ROOT = "D:\\Projects\\MCP"

    fun setup(testRunId: String, serverIdentity: String): String = listOf(
        "\$ErrorActionPreference = 'Stop'",
        "Set-Location -LiteralPath '${escapeSingleQuoted(PROJECT_ROOT)}'",
        ".\\scripts\\prepare-cancel-test-server.ps1 -TestRunId '${escapeSingleQuoted(testRunId)}' -ServerIdentity '${escapeSingleQuoted(serverIdentity)}'"
    ).joinToString("\r\n")

    fun testCommands(): String = listOf(
        "\$ErrorActionPreference = 'Stop'",
        "Set-Location -LiteralPath '${escapeSingleQuoted(PROJECT_ROOT)}'",
        "\$RunIdSecure = \$null",
        "\$ServerIdentitySecure = \$null",
        "\$RunIdBuffer = [IntPtr]::Zero",
        "\$ServerIdentityBuffer = [IntPtr]::Zero",
        "\$TestRunId = \$null",
        "\$ServerIdentity = \$null",
        "try {",
        "\$RunIdSecure = Read-Host -Prompt 'Paste the active Burp Run ID (hidden)' -AsSecureString",
        "\$ServerIdentitySecure = Read-Host -Prompt 'Paste the active Burp Server Identity (hidden)' -AsSecureString",
        "    \$RunIdBuffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(\$RunIdSecure)",
        "    \$ServerIdentityBuffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(\$ServerIdentitySecure)",
        "    \$TestRunId = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(\$RunIdBuffer)",
        "    \$ServerIdentity = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(\$ServerIdentityBuffer)",
        "    .\\scripts\\prepare-cancel-test-server.ps1 -TestRunId \$TestRunId -ServerIdentity \$ServerIdentity",
        "    .\\scripts\\run-cancel-test.ps1 -PromptForMcpToken -WaitForLiveSession -TestRunId \$TestRunId -ServerIdentity \$ServerIdentity",
        "} finally {",
        "    if (\$RunIdBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR(\$RunIdBuffer) }",
        "    if (\$ServerIdentityBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR(\$ServerIdentityBuffer) }",
        "    if (\$null -ne \$RunIdSecure) { \$RunIdSecure.Dispose() }",
        "    if (\$null -ne \$ServerIdentitySecure) { \$ServerIdentitySecure.Dispose() }",
        "    \$TestRunId = \$null",
        "    \$ServerIdentity = \$null",
        "}"
    ).joinToString("\r\n")

    private fun escapeSingleQuoted(value: String): String = value.replace("'", "''")
}
