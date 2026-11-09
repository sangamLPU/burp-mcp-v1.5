$ErrorActionPreference = 'Stop'
$assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:assertions++
}
function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Message)
    if ($Expected -cne $Actual) { throw "ASSERTION FAILED: $Message (expected '$Expected', got '$Actual')" }
    $script:assertions++
}

$fixtureScript = Join-Path $PSScriptRoot 'prepare-cancel-test-server.ps1'
$repoRoot = Split-Path -Parent $PSScriptRoot
$testRunId = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
$bytes = New-Object byte[] 32
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($bytes) } finally { $random.Dispose() }
$serverIdentity = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$previousEnvironment = @{}
foreach ($name in @('BURP_MCP_TOKEN', 'BURP_TEST_RUN_ID', 'BURP_TEST_SERVER_IDENTITY')) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$ownedProcessId = $null

try {
    if (-not (Test-Path -LiteralPath $fixtureScript -PathType Leaf)) { throw 'Fixture coordinator script is missing.' }
    $existing = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) { throw '127.0.0.1:8000 is occupied; fixture handoff test will not touch an existing process.' }

    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', 'Z' * 43, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_RUN_ID', $testRunId, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', $serverIdentity, 'Process')
    $ready = @(& $fixtureScript -IdentityFromEnvironment -PassThru)
    Assert-Equal 1 $ready.Count 'fixture preparation should return exactly one structured result'
    $fixture = $ready[0]
    $ownedProcessId = [int]$fixture.ProcessId
    Assert-Equal 'READY' $fixture.State 'fixture should report READY after its direct identity health check'
    Assert-Equal '127.0.0.1:8000' $fixture.LoopbackEndpoint 'fixture should bind only the expected loopback endpoint'
    Assert-True ([string]$fixture.HealthCheck -match '^PASS') 'health check should confirm matching active identities'
    Assert-True ($ownedProcessId -gt 0 -and $null -ne (Get-Process -Id $ownedProcessId -ErrorAction SilentlyContinue)) 'coordinator should return its started fixture PID'

    $listener = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue |
        Where-Object OwningProcess -eq $ownedProcessId)
    Assert-Equal 1 $listener.Count 'the returned fixture PID should own the sole loopback listener'

    $readyJson = $fixture | ConvertTo-Json -Depth 4 -Compress
    Assert-True (-not $readyJson.Contains($testRunId) -and -not $readyJson.Contains($serverIdentity)) 'structured fixture result must not disclose identity values'
    $processCommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $ownedProcessId").CommandLine
    Assert-True (-not $processCommandLine.Contains($testRunId) -and -not $processCommandLine.Contains($serverIdentity)) 'fixture identities must be inherited through process environment, not process arguments'
    Assert-True (-not $processCommandLine.Contains(('Z' * 43))) 'MCP token must not be inherited by the origin fixture'

    $prepareSource = Get-Content -LiteralPath $fixtureScript -Raw
    Assert-True ($prepareSource.Contains("SetEnvironmentVariable('BURP_MCP_TOKEN', `$null, 'Process')")) 'fixture launcher should clear the MCP bearer token before creating the child'

    Write-Output ("PASS: {0} fixture coordinator assertions; actual identity-bound fixture startup, hidden environment handoff, readiness response, and owned-process cleanup verified. Only direct loopback health traffic was sent." -f $assertions)
} finally {
    if ($null -ne $ownedProcessId) {
        $owner = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue |
            Where-Object OwningProcess -eq $ownedProcessId)
        if ($owner.Count -gt 0) { Stop-Process -Id $ownedProcessId -Force -ErrorAction SilentlyContinue }
    }
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    $previousEnvironment.Clear()
}

$remaining = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue)
if ($remaining.Count -gt 0) { throw 'Fixture coordinator failed to release its owned localhost listener.' }
