param(
    [switch]$PromptForMcpToken,
    [switch]$AuthOnly,
    [switch]$WaitForLiveSession,
    [switch]$OfflineSimulationNoTraffic,
    [ValidateRange(150, 600)] [int]$MinimumSessionSeconds = 300,
    [string]$CoordinatorStatePath = '',
    [string]$TestRunId = [Environment]::GetEnvironmentVariable('BURP_TEST_RUN_ID', 'Process'),
    [string]$ServerIdentity = [Environment]::GetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', 'Process')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cancel-test-auth.ps1')
. (Join-Path $PSScriptRoot 'cancel-test-validation.ps1')

$preflightScript = Join-Path $PSScriptRoot 'cancel_test_preflight.py'
if (-not (Test-Path -LiteralPath $preflightScript -PathType Leaf)) {
    throw 'Cancellation preflight script is missing; request was not sent.'
}
$python = Get-Command 'python.exe' -ErrorAction Stop
$previousToken = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
$previousTestRunId = [Environment]::GetEnvironmentVariable('BURP_TEST_RUN_ID', 'Process')
$previousServerIdentity = [Environment]::GetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', 'Process')

function Write-CancelCoordinatorState {
    param([Parameter(Mandatory = $true)] [hashtable]$State)
    if ([string]::IsNullOrWhiteSpace($CoordinatorStatePath)) { return }
    $path = [System.IO.Path]::GetFullPath($CoordinatorStatePath)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char] '\') + '\'
    if (-not $path.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Coordinator state file must be inside the current user temporary directory.'
    }
    $json = $State | ConvertTo-Json -Depth 5 -Compress
    [System.IO.File]::WriteAllText($path, $json, [System.Text.UTF8Encoding]::new($false))
}

if (-not [string]::IsNullOrWhiteSpace($CoordinatorStatePath)) {
    $stateDirectory = Split-Path -Parent ([System.IO.Path]::GetFullPath($CoordinatorStatePath))
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        throw 'Coordinator state directory does not exist; no request was sent.'
    }
}
try {
    if ($AuthOnly) {
        $null = Invoke-CancelTestAuthentication -PythonPath $python.Source -PreflightScript $preflightScript -PromptForMcpToken:$PromptForMcpToken
        Write-Host 'AUTH PASS: authenticated MCP initialization and read-only status succeeded; token was not displayed.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($TestRunId) -xor [string]::IsNullOrWhiteSpace($ServerIdentity)) {
        throw 'Supply both -TestRunId and -ServerIdentity from the active Burp-local mode, or supply neither; request was not sent.'
    }
    if ($TestRunId -and $TestRunId -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
        throw 'TestRunId is malformed; request was not sent.'
    }
    if ($ServerIdentity -and $ServerIdentity -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'ServerIdentity is malformed; request was not sent.'
    }
    [Environment]::SetEnvironmentVariable('BURP_TEST_RUN_ID', $TestRunId, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', $ServerIdentity, 'Process')

    if ($WaitForLiveSession) {
        Invoke-CancelTestPreflightProcess -PythonPath $python.Source -PreflightScript $preflightScript -PreflightArguments @('--setup-only') -PromptForMcpToken:$PromptForMcpToken
        Write-Host 'Setup is complete. Activate the fresh interception session in Burp, then resume this runner for one fast final preflight.'
        Read-Host -Prompt 'After the approved 300-second session is active, press Enter once to run the final preflight and one request; Ctrl+C cancels'
    }
    $finalPreflightArguments = @()
    if ($MinimumSessionSeconds -ne 300) {
        $finalPreflightArguments = @('--minimum-session-seconds', "$MinimumSessionSeconds")
    }
    Invoke-CancelTestPreflightProcess -PythonPath $python.Source -PreflightScript $preflightScript -PreflightArguments $finalPreflightArguments -PromptForMcpToken:$PromptForMcpToken
} finally {
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $previousToken, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_RUN_ID', $previousTestRunId, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', $previousServerIdentity, 'Process')
    $previousToken = $null
    $previousTestRunId = $null
    $previousServerIdentity = $null
}

if ($OfflineSimulationNoTraffic) {
    Write-Output 'OFFLINE SIMULATION PASS: fixture-ready pause/resume and one authenticated final preflight completed; no cancellation request was sent.'
    return
}

$proxyHost = '127.0.0.1'
$proxyPort = 8080
$targetHost = '127.0.0.1'
$targetPort = 8000
$targetPath = '/test-cancel'
$targetUrl = "http://$targetHost`:$targetPort$targetPath"
$testId = 'phase4a-' + [Guid]::NewGuid().ToString('N')
$null = Write-CancelCoordinatorState -State @{
    phase = 'Prepared'
    testId = $testId
    targetPath = $targetPath
    requestSent = $false
    timestampUtc = [DateTime]::UtcNow.ToString('o')
}
$crlf = [string]([char]13) + [char]10
$logPath = Join-Path $PSScriptRoot '..\build\live-test-server-observations.jsonl'

$baselineLines = @()
if (Test-Path -LiteralPath $logPath -PathType Leaf) {
    $baselineLines = @(Get-Content -LiteralPath $logPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

$requestLines = [System.Collections.Generic.List[string]]::new()
$requestLines.Add("GET $targetUrl HTTP/1.1")
$requestLines.Add("Host: $targetHost`:$targetPort")
$requestLines.Add("X-MCP-Test-ID: $testId")
if ($TestRunId) {
    $requestLines.Add("X-MCP-Test-Run: $TestRunId")
    $requestLines.Add("X-MCP-Server-Identity: $ServerIdentity")
}
$requestLines.Add('Connection: close')
$requestLines.Add('')
$requestLines.Add('')
$requestText = $requestLines -join $crlf
$requestBytes = [System.Text.Encoding]::ASCII.GetBytes($requestText)
$client = [System.Net.Sockets.TcpClient]::new()
$client.SendTimeout = 10000
$client.ReceiveTimeout = 125000
$clientOutcome = 'NotSent'
$clientBytesObserved = 0
$clientObservation = $null
$readTermination = 'Open'
$responseMemory = [System.IO.MemoryStream]::new()

try {
    $connectTask = $client.ConnectAsync($proxyHost, $proxyPort)
    if (-not $connectTask.Wait(10000)) {
        throw 'Timed out connecting to local Burp Proxy; request was not sent and will not be retried.'
    }
    $null = $connectTask.GetAwaiter().GetResult()
    $stream = $client.GetStream()
    $stream.Write($requestBytes, 0, $requestBytes.Length)
    $stream.Flush()
    $null = Write-CancelCoordinatorState -State @{
        phase = 'RequestSent'
        testId = $testId
        targetPath = $targetPath
        requestSent = $true
        timestampUtc = [DateTime]::UtcNow.ToString('o')
    }

    [pscustomobject]@{
        State = 'Request sent once; leave this PowerShell process running while the held request is dropped in Burp.'
        Target = $targetUrl
        Proxy = "$proxyHost`:$proxyPort"
        TestId = $testId
        AutomaticRetries = $false
        ReceiveDeadlineSeconds = 125
    } | Format-List

    $buffer = New-Object byte[] 4096
    $readClock = [System.Diagnostics.Stopwatch]::StartNew()
    $readDeadlineMilliseconds = 125000
    while ($true) {
        $remainingMilliseconds = $readDeadlineMilliseconds - [int]$readClock.ElapsedMilliseconds
        if ($remainingMilliseconds -le 0) {
            $readTermination = 'ReadTimeout'
            break
        }
        $client.ReceiveTimeout = $remainingMilliseconds
        try {
            $readCount = $stream.Read($buffer, 0, $buffer.Length)
        } catch {
            $readTermination = Get-CancelSocketTermination -Exception $_.Exception
            break
        }
        if ($readCount -eq 0) {
            $readTermination = 'EOF'
            break
        }
        $clientBytesObserved += $readCount
        if (($responseMemory.Length + $readCount) -gt 1048576) {
            $readTermination = 'ResponseTooLarge'
            break
        }
        $responseMemory.Write($buffer, 0, $readCount)
        $clientObservation = Get-CancelClientObservation -ResponseBytes $responseMemory.ToArray() -Termination Open
        if ($clientObservation.Outcome -notin @('NoDataYet', 'ResponseInProgress')) {
            break
        }
    }
    $clientObservation = Get-CancelClientObservation -ResponseBytes $responseMemory.ToArray() -Termination $readTermination
    $clientOutcome = $clientObservation.Outcome

    $allLines = @()
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $allLines = @(Get-Content -LiteralPath $logPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $newLines = @($allLines | Select-Object -Skip $baselineLines.Count)
    $newRecords = @($newLines | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
    $serverEvidence = Test-CancelServerDeliveryEvidence -Records $newRecords -TestId $testId
    $serverVerified = $serverEvidence.VerifiedSingleDelivery
    $validation = Test-CancelInterceptionObservation -ClientOutcome $clientOutcome -ClientStatusCode $clientObservation.HttpStatusCode -ServerRequestCount $serverEvidence.ServerRequestsToTestPath

    $null = Write-CancelCoordinatorState -State @{
        phase = 'Complete'
        testId = $testId
        targetPath = $targetPath
        requestSent = $true
        clientOutcome = $clientOutcome
        clientHttpStatusCode = $clientObservation.HttpStatusCode
        serverRequestsToTestPath = $serverEvidence.ServerRequestsToTestPath
        matchingTestIdRecords = $serverEvidence.MatchingTestIdRecords
        validationPassed = [bool]$validation.Passed
        failedConditions = @($validation.FailedConditions)
        timestampUtc = [DateTime]::UtcNow.ToString('o')
    }

    [pscustomobject]@{
        ClientOriginEvidence = if ($validation.Passed) { 'PASS' } else { 'FAIL' }
        ClientOutcome = $clientOutcome
        ClientBytesObserved = $clientBytesObserved
        ClientHttpStatusCode = $clientObservation.HttpStatusCode
        ClientFraming = $clientObservation.Framing
        ClientExpectedBodyBytes = $clientObservation.ExpectedBodyBytes
        ClientBodyBytesObserved = $clientObservation.BodyBytesObserved
        ServerRequestsToTestPath = $serverEvidence.ServerRequestsToTestPath
        MatchingTestIdRecords = $serverEvidence.MatchingTestIdRecords
        ServerVerifiedIfReached = $serverVerified
        FailedConditions = ($validation.FailedConditions -join ', ')
        AutomaticRetries = $false
    } | Format-List

    if (-not $validation.Passed) {
        throw "Cancellation client/origin evidence failed: $($validation.FailedConditions -join ', '). The request was sent once; do not retry it."
    }
} finally {
    $responseMemory.Dispose()
    $client.Dispose()
}
