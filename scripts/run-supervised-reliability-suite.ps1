[CmdletBinding()]
param(
    [ValidateSet('OFFLINE', 'LOCAL', 'SUPERVISED')]
    [string]$Mode = 'OFFLINE',
    [ValidateRange(30, 1800)]
    [int]$PerTestTimeoutSeconds = 300,
    [ValidateRange(150, 600)]
    [int]$SessionLifetimeSeconds = 180,
    [ValidateRange(5, 45)]
    [int]$QueueWaitSeconds = 35,
    [ValidateRange(180, 1800)]
    [int]$OverallTimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$preflightScript = Join-Path $PSScriptRoot 'cancel_test_preflight.py'
$fixtureScript = Join-Path $PSScriptRoot 'prepare-cancel-test-server.ps1'
$runnerScript = Join-Path $PSScriptRoot 'run-cancel-test.ps1'
$validationScript = Join-Path $PSScriptRoot 'run-full-validation.ps1'
$reportDirectory = Join-Path $repoRoot 'build\reports'
$null = New-Item -ItemType Directory -Force -Path $reportDirectory
$startedAt = [DateTime]::UtcNow
$runTag = $startedAt.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$reportJson = Join-Path $reportDirectory "supervised-reliability-$runTag.json"
$reportMarkdown = Join-Path $reportDirectory "supervised-reliability-$runTag.md"
$results = [System.Collections.Generic.List[object]]::new()
$overall = 'INCONCLUSIVE'
$failureMessage = $null
$failureStage = $null
$fixtureProcessId = $null
$sessionStartRequested = $false
$sessionStopAttempted = $false
$sessionStopped = $false
$runnerProcess = $null
$identityResult = $null
$dropResult = $null
$runnerState = $null
$runDirectory = $null
$previousEnvironment = @{}
foreach ($name in @('BURP_MCP_TOKEN', 'BURP_TEST_RUN_ID', 'BURP_TEST_SERVER_IDENTITY')) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

. (Join-Path $PSScriptRoot 'cancel-test-auth.ps1')

function Add-CoordinatorResult {
    param([string]$Name, [ValidateSet('PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE', 'UNVERIFIED')] [string]$Status, [string]$Evidence)
    $safe = $Evidence -replace '[\r\n]+', ' '
    $token = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($token)) { $safe = $safe.Replace($token, '[redacted]') }
    $results.Add([pscustomobject]@{ name = $Name; status = $Status; evidence = $safe })
}

function Invoke-CoordinatorPreflight {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]]$Arguments, [switch]$CaptureOutput)
    if ($CaptureOutput) {
        return Invoke-CancelTestPreflightProcess -PythonPath $script:python.Source -PreflightScript $script:preflightScript `
            -PreflightArguments $Arguments -PromptForMcpToken -ReturnResult
    }
    Invoke-CancelTestPreflightProcess -PythonPath $script:python.Source -PreflightScript $script:preflightScript `
        -PreflightArguments $Arguments -PromptForMcpToken
}

function ConvertFrom-CoordinatorJson {
    param([Parameter(Mandatory = $true)] [string]$Text, [Parameter(Mandatory = $true)] [string]$Description)
    try { return $Text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "$Description returned malformed bounded JSON; no later action was taken." }
}

function Test-OwnedFixtureListener {
    param([Parameter(Mandatory = $true)] [int]$ProcessId)
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue)
    return ($null -ne $process -and @($listeners | Where-Object OwningProcess -eq $ProcessId).Count -gt 0)
}

function Start-CancelRunnerChild {
    param([Parameter(Mandatory = $true)] [string]$StatePath)
    $powershellExe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($powershellExe)) { throw 'Could not resolve the current PowerShell executable.' }
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:runnerScript,
        '-PromptForMcpToken', '-MinimumSessionSeconds', "$script:sessionLifetimeSeconds",
        '-CoordinatorStatePath', $StatePath
    )
    $quoted = @($arguments | ForEach-Object { ConvertTo-CancelTestProcessArgument -Value $_ }) -join ' '
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $powershellExe
    $startInfo.Arguments = $quoted
    $startInfo.WorkingDirectory = $script:repoRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($name in @('BURP_MCP_TOKEN', 'BURP_TEST_RUN_ID', 'BURP_TEST_SERVER_IDENTITY')) {
        $startInfo.EnvironmentVariables[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'Cancellation runner child did not start.' }
    $script:runnerStdoutTask = $process.StandardOutput.ReadToEndAsync()
    $script:runnerStderrTask = $process.StandardError.ReadToEndAsync()
    return $process
}

try {
    if ($Mode -in @('OFFLINE', 'LOCAL')) {
        $validationExe = (Get-Process -Id $PID).Path
        $validationArguments = @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $validationScript,
            '-Mode', $Mode, '-PerTestTimeoutSeconds', "$PerTestTimeoutSeconds"
        )
        $quoted = @($validationArguments | ForEach-Object { ConvertTo-CancelTestProcessArgument -Value $_ }) -join ' '
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $validationExe
        $startInfo.Arguments = $quoted
        $startInfo.WorkingDirectory = $repoRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $validationProcess = [System.Diagnostics.Process]::new()
        try {
            $validationProcess.StartInfo = $startInfo
            if (-not $validationProcess.Start()) { throw 'Full validation child did not start.' }
            $stdoutTask = $validationProcess.StandardOutput.ReadToEndAsync()
            $stderrTask = $validationProcess.StandardError.ReadToEndAsync()
            if (-not $validationProcess.WaitForExit($OverallTimeoutSeconds * 1000)) {
                try { $validationProcess.Kill() } catch { }
                throw "Full $Mode validation exceeded the $OverallTimeoutSeconds-second overall timeout."
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if (-not [string]::IsNullOrWhiteSpace($stdout)) { Write-Host $stdout.TrimEnd() }
            if (-not [string]::IsNullOrWhiteSpace($stderr)) { Write-Host $stderr.TrimEnd() }
            $fullReportDirectory = Join-Path $reportDirectory 'full-validation'
            $fullReportFile = Get-ChildItem -LiteralPath $fullReportDirectory -Filter 'validation-*.json' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
            if ($null -eq $fullReportFile) {
                $overall = 'FAIL'
                Add-CoordinatorResult 'Full validation child' 'FAIL' 'run-full-validation.ps1 did not produce its machine-readable result report.'
            } else {
                $fullReport = Get-Content -LiteralPath $fullReportFile.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                $fullCounts = $fullReport.counts
                if ($null -eq $fullCounts -or $null -eq $fullCounts.PASS -or $null -eq $fullCounts.FAIL -or
                    $null -eq $fullCounts.BLOCKED -or $null -eq $fullCounts.INCONCLUSIVE -or $null -eq $fullCounts.UNVERIFIED) {
                    throw 'Full validation result report omitted required outcome counts.'
                }
                $countEvidence = "PASS=$($fullCounts.PASS), FAIL=$($fullCounts.FAIL), BLOCKED=$($fullCounts.BLOCKED), INCONCLUSIVE=$($fullCounts.INCONCLUSIVE), UNVERIFIED=$($fullCounts.UNVERIFIED), UNSUPPORTED=$($fullCounts.UNSUPPORTED); report=$(Split-Path -Leaf $fullReportFile.FullName)"
                if ($validationProcess.ExitCode -ne 0 -or [int]$fullCounts.FAIL -gt 0) {
                    $overall = 'FAIL'
                    Add-CoordinatorResult 'Full validation child' 'FAIL' $countEvidence
                } elseif ([int]$fullCounts.BLOCKED -gt 0) {
                    $overall = 'BLOCKED'
                    Add-CoordinatorResult 'Full validation child' 'BLOCKED' $countEvidence
                } elseif ([int]$fullCounts.INCONCLUSIVE -gt 0 -or [int]$fullCounts.UNVERIFIED -gt 0) {
                    $overall = 'INCONCLUSIVE'
                    Add-CoordinatorResult 'Full validation child' 'INCONCLUSIVE' $countEvidence
                } else {
                    $overall = 'PASS'
                    Add-CoordinatorResult 'Full validation child' 'PASS' $countEvidence
                }
            }
        } finally { $validationProcess.Dispose() }
    } else {
        $script:sessionLifetimeSeconds = $SessionLifetimeSeconds
        $script:preflightScript = $preflightScript
        $script:runnerScript = $runnerScript
        $script:repoRoot = $repoRoot
        $python = Get-Command 'python.exe' -ErrorAction Stop
        $script:python = $python
        if (-not (Test-Path -LiteralPath $preflightScript -PathType Leaf) -or
            -not (Test-Path -LiteralPath $fixtureScript -PathType Leaf) -or
            -not (Test-Path -LiteralPath $runnerScript -PathType Leaf)) {
            throw 'Supervised cancellation scripts are incomplete; no fixture or live session was started.'
        }
        $listenersBefore = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue)
        if ($listenersBefore.Count -gt 0) {
            $overall = 'BLOCKED'
            throw 'Port 8000 is already occupied; the coordinator will not stop or replace an existing process.'
        }

        $failureStage = 'authenticated identity and scope preflight'
        $identityResult = Invoke-CoordinatorPreflight -Arguments @('--coordinator-identities', "$SessionLifetimeSeconds") -CaptureOutput
        if ($identityResult.ExitCode -ne 0) {
            $details = ([string]$identityResult.StdErr).Trim()
            if ($details -match '(?i)unattended local test mode is not active|authorization has less than|interception must be inactive') {
                $overall = 'BLOCKED'
                Add-CoordinatorResult 'Activation and identity prerequisite' 'BLOCKED' $details
                throw "SUPERVISED BLOCKED: $details"
            }
            throw "Authenticated supervised preflight failed (Python exit code $($identityResult.ExitCode)). $details"
        }
        $identities = ConvertFrom-CoordinatorJson -Text ([string]$identityResult.StdOut) -Description 'Identity discovery'
        $runId = [string]$identities.testRunId
        $serverIdentity = [string]$identities.serverIdentity
        if ($runId -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' -or
            $serverIdentity -notmatch '^[A-Za-z0-9_-]{43}$' -or
            [int]$identities.scopeEligibleCount -ne 9) {
            throw 'Authenticated identity discovery did not verify all nine fixed localhost targets.'
        }
        [Environment]::SetEnvironmentVariable('BURP_TEST_RUN_ID', $runId, 'Process')
        [Environment]::SetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', $serverIdentity, 'Process')
        $runId = $null
        $serverIdentity = $null
        $identities = $null
        Add-CoordinatorResult 'MCP authentication, runtime, identity, and nine-target scope' 'PASS' 'Authenticated MCP preflight matched loaded build, Burp version, active identities, allowlist, scope, and empty queues; identity values were held in process memory only.'

        $failureStage = 'identity-bound fixture startup'
        $fixtureReady = @(& $fixtureScript -IdentityFromEnvironment -PassThru)
        if ($fixtureReady.Count -ne 1 -or $fixtureReady[0].State -ne 'READY' -or
            $fixtureReady[0].LoopbackEndpoint -ne '127.0.0.1:8000' -or
            [string]$fixtureReady[0].HealthCheck -notmatch '^PASS') {
            throw 'Local fixture did not return one structured READY result.'
        }
        $fixtureProcessId = [int]$fixtureReady[0].ProcessId
        if (-not (Test-OwnedFixtureListener -ProcessId $fixtureProcessId)) {
            throw 'Identity-bound local fixture is not listening under the process started by this coordinator.'
        }
        Add-CoordinatorResult 'Local fixture' 'PASS' 'Bounded 127.0.0.1:8000 fixture is healthy and returned matching active identities; the health request used the direct local socket and was excluded from origin evidence.'

        $failureStage = 'setup preflight'
        Invoke-CoordinatorPreflight -Arguments @('--setup-only')
        Add-CoordinatorResult 'Setup preflight before interception' 'PASS' 'Authentication, fixture health and identity, nine-target scope, inactive interception, and empty queues passed before session creation.'

        $failureStage = 'policy-authorized interception session start'
        $sessionStartRequested = $true
        $sessionResult = Invoke-CoordinatorPreflight -Arguments @('--start-session', "$SessionLifetimeSeconds") -CaptureOutput
        if ($sessionResult.ExitCode -ne 0) {
            $details = ([string]$sessionResult.StdErr).Trim()
            throw "Policy-bounded live session did not start (Python exit code $($sessionResult.ExitCode)). $details"
        }
        $sessionSummary = ConvertFrom-CoordinatorJson -Text ([string]$sessionResult.StdOut) -Description 'Session start'
        if ($sessionSummary.enabled -ne $true -or $sessionSummary.heartbeatHealth -ne 'HEALTHY' -or
            [int]$sessionSummary.pendingRequests -ne 0 -or [int]$sessionSummary.pendingResponses -ne 0 -or
            [int]$sessionSummary.sessionRemainingMillis -lt 150000 -or
            [int]$sessionSummary.authorizationRemainingMillis -lt 150000) {
            throw 'Live session, heartbeat, deadlines, or queue checks failed immediately after start.'
        }
        Add-CoordinatorResult 'Fresh live interception session' 'PASS' "$SessionLifetimeSeconds-second policy-bounded session is active, heartbeat healthy, both queues empty, and both deadlines exceed 150 seconds."

        $failureStage = 'one-shot cancellation request and policy drop'
        $runDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("burp-mcp-phase4a-{0}" -f [Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $runDirectory -Force
        $statePath = Join-Path $runDirectory 'runner-state.json'
        $runnerProcess = Start-CancelRunnerChild -StatePath $statePath
        $dropResult = Invoke-CoordinatorPreflight -Arguments @('--drop-matching-request', "$QueueWaitSeconds") -CaptureOutput
        if ($dropResult.ExitCode -ne 0) {
            $details = ([string]$dropResult.StdErr).Trim()
            throw "The exact held request was not automatically dropped (Python exit code $($dropResult.ExitCode)). $details"
        }
        $dropSummary = ConvertFrom-CoordinatorJson -Text ([string]$dropResult.StdOut) -Description 'Drop verification'
        if ($dropSummary.dropState -ne 'DROPPED' -or $dropSummary.approvalMode -ne 'AUTOMATIC' -or
            $dropSummary.automaticApprovalEvidence -ne $true -or
            $dropSummary.staleGetRejected -ne $true -or $dropSummary.staleEditRejected -ne $true -or
            $dropSummary.staleForwardRejected -ne $true -or
            [int]$dropSummary.pendingRequests -ne 0 -or [int]$dropSummary.pendingResponses -ne 0) {
            throw 'Drop state, automatic-approval attribution, stale-ID protection, or queue cleanup was not fully verified.'
        }
        Add-CoordinatorResult 'Exact request drop and stale-ID rejection' 'PASS' 'Burp diagnostic state was DROPPED; unattended policy audit attributes automatic DROP_REQUEST approval; stale read/edit/forward operations were rejected; both queues are empty.'

        $failureStage = 'bounded client and zero-origin verification'
        if (-not $runnerProcess.WaitForExit(130000)) {
            try { $runnerProcess.Kill() } catch { }
            throw 'Cancellation runner did not reach a terminal outcome within its 125-second client deadline plus 5-second cleanup margin.'
        }
        $runnerStdout = $script:runnerStdoutTask.GetAwaiter().GetResult()
        $runnerStderr = $script:runnerStderrTask.GetAwaiter().GetResult()
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            throw "Cancellation runner exited $($runnerProcess.ExitCode) without coordinator evidence."
        }
        $runnerState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($runnerProcess.ExitCode -ne 0 -or $runnerState.phase -ne 'Complete' -or
            $runnerState.requestSent -ne $true -or $runnerState.validationPassed -ne $true -or
            [int]$runnerState.serverRequestsToTestPath -ne 0 -or
            $runnerState.clientOutcome -notin @('EOFWithoutResponse', 'ConnectionReset', 'ConnectionAborted') -and
                -not ($runnerState.clientOutcome -eq 'HttpResponseComplete' -and [int]$runnerState.clientHttpStatusCode -ge 400 -and [int]$runnerState.clientHttpStatusCode -le 599)) {
            $safeStderr = ([string]$runnerStderr -replace '[\r\n]+', ' ').Trim()
            if ($safeStderr.Length -gt 300) { $safeStderr = $safeStderr.Substring(0, 300) }
            throw "Client/origin validator failed or did not complete. Runner exit=$($runnerProcess.ExitCode); outcome=$($runnerState.clientOutcome); originRequests=$($runnerState.serverRequestsToTestPath). $safeStderr"
        }
        if (-not (Test-OwnedFixtureListener -ProcessId $fixtureProcessId)) {
            throw 'Origin process or loopback listener stopped before zero-delivery evidence was finalized.'
        }
        Add-CoordinatorResult 'Bounded client outcome and zero origin delivery' 'PASS' "The fixture remained live throughout the request; the unchanged fail-closed validator accepted client outcome $($runnerState.clientOutcome); origin deliveries to /test-cancel were $($runnerState.serverRequestsToTestPath)."

        $failureStage = 'session cleanup'
        $sessionStopAttempted = $true
        $stopResult = Invoke-CoordinatorPreflight -Arguments @('--stop-session-if-safe') -CaptureOutput
        if ($stopResult.ExitCode -ne 0) {
            throw "Queues were verified empty but the policy-safe session stop failed (Python exit code $($stopResult.ExitCode))."
        }
        $stopSummary = ConvertFrom-CoordinatorJson -Text ([string]$stopResult.StdOut) -Description 'Session cleanup'
        if ($stopSummary.stopped -ne $true) { throw 'Policy-safe live session shutdown was not confirmed.' }
        $sessionStopped = $true
        Add-CoordinatorResult 'Interception shutdown' 'PASS' 'The mode-bound session stopped through the existing policy-aware control after queue cleanup.'
        Add-CoordinatorResult 'Phase 4A' 'PASS' 'All required evidence was collected: exact held request, automatic policy drop, DROPPED diagnostic state, zero origin deliveries while origin remained live, bounded terminal client outcome, stale-ID read/edit/forward rejection, and empty queues.'
        $overall = 'PASS'
    }
} catch {
    $failureMessage = $_.Exception.Message -replace '[\r\n]+', ' '
    if ($failureStage -eq 'authenticated identity and scope preflight' -and
        $failureMessage -match '(?i)unattended local test mode is not active|authorization has less than|interception must be inactive') {
        $overall = 'BLOCKED'
    } elseif ($overall -ne 'BLOCKED') {
        $overall = if ($failureStage -eq 'policy-authorized interception session start' -or
            $failureStage -eq 'one-shot cancellation request and policy drop' -or
            $failureStage -eq 'bounded client and zero-origin verification') { 'INCONCLUSIVE' } else { 'FAIL' }
    }
    $failureName = if ([string]::IsNullOrWhiteSpace($failureStage)) { 'Coordinator' } else { $failureStage }
    Add-CoordinatorResult $failureName $overall $failureMessage
} finally {
    if ($Mode -eq 'SUPERVISED') {
        if ($sessionStartRequested -and -not $sessionStopped -and -not $sessionStopAttempted) {
            $sessionStopAttempted = $true
            try {
                $null = Invoke-CoordinatorPreflight -Arguments @('--stop-session-if-safe') -CaptureOutput
                Add-CoordinatorResult 'Best-effort policy-safe session cleanup' 'PASS' 'The existing stop control was invoked once after the coordinator checked queues and identity binding.'
            } catch {
                Add-CoordinatorResult 'Best-effort policy-safe session cleanup' 'INCONCLUSIVE' 'No unsafe emergency action was taken; the bounded live session and unattended authorization will expire automatically.'
            }
        }
        if ($null -ne $runnerProcess) {
            if (-not $runnerProcess.HasExited) {
                try { $runnerProcess.Kill() } catch { }
            }
            $runnerProcess.Dispose()
        }
        if ($null -ne $fixtureProcessId) {
            $owned = Get-Process -Id $fixtureProcessId -ErrorAction SilentlyContinue
            if ($null -ne $owned) { Stop-Process -Id $fixtureProcessId -Force -ErrorAction SilentlyContinue }
        }
        foreach ($name in $previousEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
        }
        $previousEnvironment.Clear()
    }
    $finishedAt = [DateTime]::UtcNow
    $report = [ordered]@{
        runId = $runTag
        mode = $Mode
        outcome = $overall
        startedAtUtc = $startedAt.ToString('o')
        finishedAtUtc = $finishedAt.ToString('o')
        durationSeconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 2)
        expectedBuildId = '20261101.5-burp2024.1.1.1'
        sessionLifetimeRequestedSeconds = if ($Mode -eq 'SUPERVISED') { $SessionLifetimeSeconds } else { $null }
        phase4a = if ($Mode -eq 'SUPERVISED' -and $overall -eq 'PASS') { 'PASS' } elseif ($Mode -eq 'SUPERVISED') { $overall } else { 'NOT_RUN' }
        evidence = if ($null -ne $runnerState) {
            [ordered]@{
                requestSent = [bool]$runnerState.requestSent
                clientOutcome = $runnerState.clientOutcome
                clientStatusCode = $runnerState.clientHttpStatusCode
                originRequestsToTestPath = $runnerState.serverRequestsToTestPath
                runnerValidatorPassed = $runnerState.validationPassed
                dropState = if ($null -ne $dropSummary) { $dropSummary.dropState } else { $null }
                approvalMode = if ($null -ne $dropSummary) { $dropSummary.approvalMode } else { $null }
                staleGetRejected = if ($null -ne $dropSummary) { $dropSummary.staleGetRejected } else { $null }
                staleEditRejected = if ($null -ne $dropSummary) { $dropSummary.staleEditRejected } else { $null }
                staleForwardRejected = if ($null -ne $dropSummary) { $dropSummary.staleForwardRejected } else { $null }
            }
        } else { $null }
        failure = $failureMessage
        results = @($results)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportJson -Encoding UTF8
    $markdown = [System.Collections.Generic.List[string]]::new()
    $markdown.Add('# Supervised reliability suite')
    $markdown.Add('')
    $markdown.Add("- Mode: $Mode")
    $markdown.Add("- Outcome: $overall")
    $markdown.Add("- Started: $($startedAt.ToString('u'))")
    $markdown.Add("- Finished: $($finishedAt.ToString('u'))")
    $markdown.Add('')
    $markdown.Add('| Check | Status | Evidence |')
    $markdown.Add('|---|---|---|')
    foreach ($item in $results) { $markdown.Add("| $($item.name) | $($item.status) | $($item.evidence -replace '\|', '\|') |") }
    $markdown.Add('')
    $markdown.Add("JSON report: $(Split-Path -Leaf $reportJson)")
    $markdown | Set-Content -LiteralPath $reportMarkdown -Encoding UTF8
    Write-Host "Coordinator reports: $reportMarkdown and $reportJson"
    Write-Host "Outcome=$overall"
    if ($null -ne $runDirectory -and (Test-Path -LiteralPath $runDirectory -PathType Container)) {
        Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($overall -eq 'FAIL') { exit 1 }
if ($overall -eq 'INCONCLUSIVE') { exit 2 }
if ($overall -eq 'BLOCKED') { exit 3 }
exit 0
