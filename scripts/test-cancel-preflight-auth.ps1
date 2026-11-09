$ErrorActionPreference = 'Stop'

$previousToken = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
try {
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', ('A' * 43), 'Process')
    $python = Get-Command 'python.exe' -ErrorAction Stop
    & $python.Source -B -c "import os,sys; sys.exit(0 if os.getenv('BURP_MCP_TOKEN') == ('A' * 43) else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw 'A Python child process did not inherit the synthetic process token.'
    }
    Write-Output 'PASS: Python child inherited the synthetic token; no token value was displayed.'
} finally {
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $previousToken, 'Process')
    $previousToken = $null
}
