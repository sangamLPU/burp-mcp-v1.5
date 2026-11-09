param(
    [ValidateSet('OFFLINE', 'LOCAL', 'SUPERVISED')]
    [string]$Mode = 'OFFLINE',
    [switch]$BuildCandidate,
    [switch]$ForceTestExecution,
    [ValidateRange(60, 7200)]
    [int]$OverallTimeoutSeconds = 1800,
    [ValidateRange(30, 1800)]
    [int]$PerTestTimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$reportDir = Join-Path $repoRoot 'build\reports\full-validation'
$validationDir = Join-Path $repoRoot 'build\validation'
$null = New-Item -ItemType Directory -Force -Path $reportDir, $validationDir
$runId = [Guid]::NewGuid().ToString('N')
$startedAt = [DateTime]::UtcNow
$scriptTimer = [System.Diagnostics.Stopwatch]::StartNew()
$results = [System.Collections.Generic.List[object]]::new()
$reportJson = Join-Path $reportDir "validation-$runId.json"
$reportMarkdown = Join-Path $reportDir "validation-$runId.md"
$overallDeadline = [DateTime]::UtcNow.AddSeconds($OverallTimeoutSeconds)

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Evidence, [long]$DurationMs = 0)
    $results.Add([pscustomobject]@{
        name = $Name
        status = $Status
        evidence = $Evidence
        durationMs = $DurationMs
    })
}

function Invoke-BoundedCommand {
    param(
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [string[]]$Lines,
        [Parameter(Mandatory = $true)] [int]$TimeoutSeconds
    )

    $remaining = [int][Math]::Floor(($overallDeadline - [DateTime]::UtcNow).TotalSeconds)
    if ($remaining -le 0) {
        Add-Result $Name 'BLOCKED' 'Overall validation deadline reached before this command.'
        return $false
    }
    $timeout = [Math]::Min($TimeoutSeconds, $remaining)
    $safeName = $Name -replace '[^A-Za-z0-9_-]', '_'
    $cmdPath = Join-Path $validationDir "$runId-$safeName.cmd"
    $stdoutPath = Join-Path $validationDir "$runId-$safeName.out.log"
    $stderrPath = Join-Path $validationDir "$runId-$safeName.err.log"
    @('@echo off') + $Lines + '@exit /b %errorlevel%' | Set-Content -LiteralPath $cmdPath -Encoding ASCII

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $env:ComSpec
        $startInfo.Arguments = '/d /s /c ""' + $cmdPath + '""'
        $startInfo.WorkingDirectory = $repoRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $null = $process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $completed = $process.WaitForExit($timeout * 1000)
        if (-not $completed) {
            # The PID belongs to the exact cmd.exe process started above; /T bounds cleanup to its child tree.
            & taskkill.exe /PID $process.Id /T /F *> $null
            $process.WaitForExit(5000) | Out-Null
            $streamsComplete = [System.Threading.Tasks.Task]::WaitAll(
                [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 5000
            )
            if ($streamsComplete) {
                [System.IO.File]::WriteAllText($stdoutPath, $stdoutTask.Result)
                [System.IO.File]::WriteAllText($stderrPath, $stderrTask.Result)
            } else {
                [System.IO.File]::WriteAllText($stdoutPath, 'Timed out while collecting child process output.')
                [System.IO.File]::WriteAllText($stderrPath, 'Timed out while collecting child process error output.')
            }
            Add-Result $Name 'FAIL' "Timed out after $timeout seconds; only the test process tree was stopped." $timer.ElapsedMilliseconds
            return $false
        }
        $process.WaitForExit()
        $stdoutText = $stdoutTask.Result
        $stderrText = $stderrTask.Result
        [System.IO.File]::WriteAllText($stdoutPath, $stdoutText)
        [System.IO.File]::WriteAllText($stderrPath, $stderrText)
        $commandExitCode = $process.ExitCode
        if ($commandExitCode -eq 0) {
            Add-Result $Name 'PASS' "Exit code 0; output: $([System.IO.Path]::GetFileName($stdoutPath))" $timer.ElapsedMilliseconds
            return $true
        }
        Add-Result $Name 'FAIL' "Exit code $commandExitCode; stdout/stderr saved under build/validation." $timer.ElapsedMilliseconds
        return $false
    } catch {
        $safeMessage = $_.Exception.Message -replace '[\r\n]+', ' '
        Add-Result $Name 'FAIL' "Could not run bounded command ($($_.Exception.GetType().Name)): $safeMessage" $timer.ElapsedMilliseconds
        return $false
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-GradleValidationArguments {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('OFFLINE', 'LOCAL', 'SUPERVISED')] [string]$ValidationMode,
        [Parameter(Mandatory = $true)] [ValidateSet(17, 18)] [int]$ToolchainVersion,
        [switch]$BuildCandidate,
        [switch]$ForceTestExecution
    )

    $validationSetting = if ($ValidationMode -eq 'OFFLINE') { 'offline' } else { 'all' }
    $arguments = "test --offline --no-daemon --console=plain -Pvalidation.mode=$validationSetting -Pjava.toolchain.version=$ToolchainVersion"
    if ($ForceTestExecution) { $arguments = "test --rerun --offline --no-daemon --console=plain -Pvalidation.mode=$validationSetting -Pjava.toolchain.version=$ToolchainVersion" }
    if (-not $BuildCandidate) { $arguments += ' -x shadowJar' }
    return $arguments
}

try {
    # Preflight is intentionally read-only except for generated reports and bounded test logs under build/.
    $requiredPaths = @(
        'settings.gradle.kts', 'build.gradle.kts', 'gradle.properties', 'gradlew.bat',
        'src/main/kotlin', 'src/test/kotlin', 'scripts/local-test-server.ps1',
        'scripts/test-local-server.ps1', 'scripts/test-local-server-identity.ps1', 'scripts/test-cancel-validation.ps1',
        'scripts/run-supervised-reliability-suite.ps1', 'scripts/test-supervised-reliability-suite-offline.ps1',
        'scripts/test-cancel-fixture-coordinator.ps1'
    )
    $missingPaths = @($requiredPaths | Where-Object { -not (Test-Path -LiteralPath (Join-Path $repoRoot $_)) })
    if ($missingPaths.Count -eq 0) {
        Add-Result 'Project structure' 'PASS' "All $($requiredPaths.Count) required project paths exist."
    } else {
        Add-Result 'Project structure' 'FAIL' "Missing required paths: $($missingPaths -join ', ')"
    }

    $java = Get-Command java -ErrorAction SilentlyContinue
    $toolchainVersion = $null
    if ($null -ne $java) {
        $javaVersionProcess = $null
        $javaVersionText = ''
        try {
            $javaVersionInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $javaVersionInfo.FileName = $java.Source
            $javaVersionInfo.Arguments = '-version'
            $javaVersionInfo.UseShellExecute = $false
            $javaVersionInfo.CreateNoWindow = $true
            $javaVersionInfo.RedirectStandardOutput = $true
            $javaVersionInfo.RedirectStandardError = $true
            $javaVersionProcess = [System.Diagnostics.Process]::new()
            $javaVersionProcess.StartInfo = $javaVersionInfo
            $null = $javaVersionProcess.Start()
            $stdoutTask = $javaVersionProcess.StandardOutput.ReadToEndAsync()
            $stderrTask = $javaVersionProcess.StandardError.ReadToEndAsync()
            if ($javaVersionProcess.WaitForExit(5000)) {
                [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 1000) | Out-Null
                $javaVersionText = $stdoutTask.Result + [Environment]::NewLine + $stderrTask.Result
            } else {
                $javaVersionProcess.Kill()
            }
        } catch { $javaVersionText = '' }
        finally { if ($null -ne $javaVersionProcess) { $javaVersionProcess.Dispose() } }
        $javaVersionLine = ($javaVersionText -split '[\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
        $javaVersionMatch = [regex]::Match([string]$javaVersionLine, '"?(?<major>[0-9]+)(?:\.(?<minor>[0-9]+))?')
        if ($javaVersionMatch.Success) {
            $javaMajor = [int]$javaVersionMatch.Groups['major'].Value
            if ($javaMajor -eq 1 -and $javaVersionMatch.Groups['minor'].Success) {
                $javaMajor = [int]$javaVersionMatch.Groups['minor'].Value
            }
            if ($javaMajor -in @(17, 18)) {
                $toolchainVersion = $javaMajor
                Add-Result 'Java prerequisite' 'PASS' "Found Java $javaMajor at $($java.Source); compiler output remains targeted to Java 17 bytecode."
            } else {
                Add-Result 'Java prerequisite' 'FAIL' "Found Java major $javaMajor at $($java.Source); this project requires a Java 17-compatible toolchain."
            }
        } else {
            Add-Result 'Java prerequisite' 'FAIL' 'Could not determine the Java runtime version safely.'
        }
    } else { Add-Result 'Java prerequisite' 'FAIL' 'java was not found on PATH.' }

    $psFiles = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'scripts') -Filter '*.ps1' -File -Recurse)
    $parseFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $psFiles) {
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count -gt 0) { $parseFailures.Add($file.Name) }
    }
    if ($parseFailures.Count -eq 0) { Add-Result 'PowerShell syntax' 'PASS' "Parsed all $($psFiles.Count) PowerShell scripts." }
    else { Add-Result 'PowerShell syntax' 'FAIL' "Parse errors in: $($parseFailures -join ', ')" }

    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $git) {
        Add-Result 'Git health' 'BLOCKED' 'git is not available on PATH.'
    } else {
        $priorErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & git -C $repoRoot diff --check *> $null
        $diffCheckExitCode = $LASTEXITCODE
        $ErrorActionPreference = $priorErrorAction
        if ($diffCheckExitCode -eq 0) { Add-Result 'Git diff check' 'PASS' 'git diff --check completed without whitespace errors.' }
        else { Add-Result 'Git diff check' 'FAIL' 'git diff --check reported errors.' }
        $status = @(& git -C $repoRoot status --short)
        if ($LASTEXITCODE -eq 0) { Add-Result 'Git status' 'PASS' "Repository status captured ($($status.Count) changed paths); existing changes were preserved." }
        else { Add-Result 'Git status' 'FAIL' 'git status failed.' }

        $changed = @(& git -C $repoRoot diff --name-only --diff-filter=ACMRT) + @(& git -C $repoRoot ls-files --others --exclude-standard)
        $secretFinding = $false
        foreach ($relative in ($changed | Sort-Object -Unique)) {
            $path = Join-Path $repoRoot $relative
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            if ([System.IO.Path]::GetExtension($path) -in @('.jar', '.class', '.png', '.jpg', '.pcap', '.p12', '.pfx', '.key')) { continue }
            $content = [System.IO.File]::ReadAllText($path)
            if ($content -match '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}' -or
                $content -match '(?im)^\s*-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s*$') {
                $secretFinding = $true
                break
            }
        }
        if (-not $secretFinding) { Add-Result 'Changed-file secret scan' 'PASS' 'No bearer-token literal or private-key block found in changed text files.' }
        else { Add-Result 'Changed-file secret scan' 'FAIL' 'A bearer-token literal or private-key block was found; inspect locally without copying it into the report.' }
    }

    # Existing artifacts are read-only by default. Packaging is an explicit opt-in because
    # this project's test task depends on shadowJar and would otherwise replace the loaded JAR.
    $existingJar = Join-Path $repoRoot 'build\libs\burp-mcp-all.jar'
    if ($BuildCandidate -and (Test-Path -LiteralPath $existingJar -PathType Leaf)) {
        $beforeHash = Get-Sha256 $existingJar
        $backupDir = Join-Path $repoRoot 'build\backups'
        $null = New-Item -ItemType Directory -Force -Path $backupDir
        $backupPath = Join-Path $backupDir "burp-mcp-pre-validation-$beforeHash.jar"
        if (-not (Test-Path -LiteralPath $backupPath)) { Copy-Item -LiteralPath $existingJar -Destination $backupPath }
        if ((Get-Sha256 $backupPath) -eq $beforeHash) {
            Add-Result 'Pre-build JAR backup' 'PASS' "Preserved SHA-256 $beforeHash at $backupPath."
        } else { Add-Result 'Pre-build JAR backup' 'FAIL' 'Backup SHA-256 did not match the existing JAR.' }
    } elseif ($BuildCandidate) {
        Add-Result 'Pre-build JAR backup' 'UNVERIFIED' 'No existing packaged JAR was present to back up.'
    } else {
        Add-Result 'JAR overwrite policy' 'PASS' 'Candidate packaging was not requested; Gradle shadowJar is excluded and the existing artifact remains read-only.'
    }

    if ($null -ne $toolchainVersion) {
        $gradleArgs = Get-GradleValidationArguments -ValidationMode $Mode -ToolchainVersion $toolchainVersion -BuildCandidate:$BuildCandidate -ForceTestExecution:$ForceTestExecution
        $gradleLabel = if ($BuildCandidate) { 'Gradle tests and candidate packaging' } else { 'Gradle tests without JAR packaging' }
        $gradleSucceeded = Invoke-BoundedCommand $gradleLabel @("call `"$repoRoot\gradlew.bat`" $gradleArgs") $PerTestTimeoutSeconds
    } else {
        Add-Result 'Gradle automated tests' 'BLOCKED' 'No supported Java 17 or 18 toolchain was available.'
        $gradleSucceeded = $false
    }

    $powershellExe = (Get-Process -Id $PID).Path
    if (-not $powershellExe) { $powershellExe = 'powershell.exe' }
    $cancelTest = Join-Path $repoRoot 'scripts\test-cancel-validation.ps1'
    $cancelSucceeded = Invoke-BoundedCommand 'Cancellation runner offline regressions' @("`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$cancelTest`"") 60

    $concurrentTest = Join-Path $repoRoot 'scripts\test-concurrent-runner-validation.ps1'
    if (Test-Path -LiteralPath $concurrentTest) {
        $concurrentSucceeded = Invoke-BoundedCommand 'Concurrent runner offline regressions' @("`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$concurrentTest`"") 60
    } else {
        Add-Result 'Concurrent runner offline regressions' 'UNVERIFIED' 'No concurrent-runner offline regression script exists.'
        $concurrentSucceeded = $false
    }

    $pythonSuiteSucceeded = Invoke-BoundedCommand 'All Python offline regressions including final cancellation evidence' @(
        "python.exe -B -m unittest discover -s `"$PSScriptRoot`" -p test_*.py"
    ) 60
    $powershellAuthTest = Join-Path $repoRoot 'scripts\test-cancel-preflight-auth.ps1'
    $powershellAuthSucceeded = Invoke-BoundedCommand 'PowerShell child environment inheritance' @(
        "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$powershellAuthTest`""
    ) 30
    $runnerAuthTest = Join-Path $repoRoot 'scripts\test-cancel-runner-auth.ps1'
    $runnerAuthSucceeded = Invoke-BoundedCommand 'PowerShell cancellation auth fallback and process handling offline regressions' @(
        "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runnerAuthTest`""
    ) 60
    $workflowOfflineTest = Join-Path $repoRoot 'scripts\test-cancel-workflow-offline.ps1'
    $workflowOfflineSucceeded = Invoke-BoundedCommand 'Copied cancellation workflow offline orchestration regressions' @(
        "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workflowOfflineTest`""
    ) 90
    $orchestratorTest = Join-Path $repoRoot 'scripts\test-validation-orchestrator.ps1'
    $orchestratorSucceeded = Invoke-BoundedCommand 'Validation orchestrator artifact-preservation regressions' @(
        "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$orchestratorTest`""
    ) 30
    $supervisedCoordinatorTest = Join-Path $repoRoot 'scripts\test-supervised-reliability-suite-offline.ps1'
    $supervisedCoordinatorSucceeded = Invoke-BoundedCommand 'Supervised coordinator end-to-end offline regressions' @(
        "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$supervisedCoordinatorTest`""
    ) 120

    if ($Mode -in @('LOCAL', 'SUPERVISED')) {
        $localHarness = Join-Path $repoRoot 'scripts\test-local-server.ps1'
        $localSucceeded = Invoke-BoundedCommand 'Bounded localhost server tests' @("`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$localHarness`"") 180
        $identityHarness = Join-Path $repoRoot 'scripts\test-local-server-identity.ps1'
        $identitySucceeded = Invoke-BoundedCommand 'Unattended localhost identity enforcement tests' @("`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$identityHarness`"") 60
        $fixtureCoordinatorHarness = Join-Path $repoRoot 'scripts\test-cancel-fixture-coordinator.ps1'
        $fixtureCoordinatorSucceeded = Invoke-BoundedCommand 'Identity-bound cancellation fixture coordinator tests' @(
            "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$fixtureCoordinatorHarness`""
        ) 60
        $localSucceeded = $localSucceeded -and $identitySucceeded -and $fixtureCoordinatorSucceeded
        $ruleFixtureHarness = Join-Path $repoRoot 'scripts\test-live-rule-engine-fixture.ps1'
        $ruleFixtureSucceeded = Invoke-BoundedCommand 'Request response rule fixture loopback tests' @(
            "`"$powershellExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ruleFixtureHarness`""
        ) 60
        $localSucceeded = $localSucceeded -and $ruleFixtureSucceeded
    } else {
        Add-Result 'Bounded localhost server tests' 'BLOCKED' 'OFFLINE mode performs no network requests; rerun with -Mode LOCAL.'
        Add-Result 'Unattended localhost identity enforcement tests' 'BLOCKED' 'OFFLINE mode performs no network requests; rerun with -Mode LOCAL.'
        Add-Result 'Identity-bound cancellation fixture coordinator tests' 'BLOCKED' 'OFFLINE mode performs no network requests; rerun with -Mode LOCAL.'
        Add-Result 'Request response rule fixture loopback tests' 'BLOCKED' 'OFFLINE mode performs no network requests; rerun with -Mode LOCAL.'
        $localSucceeded = $false
    }

    if ($Mode -eq 'SUPERVISED') {
        Add-Result 'Burp approval-gated live tests' 'BLOCKED' 'Human must be present to approve Burp-local interception and scope dialogs; no live test was launched.'
    } else {
        Add-Result 'Burp approval-gated live tests' 'UNVERIFIED' 'No approval-gated Burp actions were invoked by this validation run.'
    }

    if ($gradleSucceeded) {
        $jarPath = Join-Path $repoRoot 'build\libs\burp-mcp-all.jar'
        if (Test-Path -LiteralPath $jarPath) {
            $jarHash = Get-Sha256 $jarPath
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
            try {
                $manifestEntry = $zip.GetEntry('META-INF/MANIFEST.MF')
                if ($null -eq $manifestEntry) { throw 'JAR manifest is missing.' }
                $reader = [System.IO.StreamReader]::new($manifestEntry.Open())
                try { $manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
            } finally { $zip.Dispose() }
            $expectedVersion = (Select-String -LiteralPath (Join-Path $repoRoot 'gradle.properties') -Pattern '^version=(.+)$').Matches[0].Groups[1].Value
            $expectedBuild = (Select-String -LiteralPath (Join-Path $repoRoot 'gradle.properties') -Pattern '^build\.id=(.+)$').Matches[0].Groups[1].Value
            if ($manifest -match [regex]::Escape("Implementation-Version: $expectedVersion") -and $manifest -match [regex]::Escape("Build-Id: $expectedBuild")) {
            Add-Result 'Existing packaged JAR metadata' 'PASS' "SHA-256 $jarHash; version $expectedVersion; build $expectedBuild."
            if ($BuildCandidate) {
                $candidateDir = Join-Path $repoRoot 'build\candidates'
                $null = New-Item -ItemType Directory -Force -Path $candidateDir
                $candidatePath = Join-Path $candidateDir "burp-mcp-$expectedVersion-$expectedBuild.jar"
                Copy-Item -LiteralPath $jarPath -Destination $candidatePath -Force
                if ((Get-Sha256 $candidatePath) -eq $jarHash) {
                    Add-Result 'Candidate JAR preservation' 'PASS' "Preserved candidate SHA-256 $jarHash at $candidatePath; runtime deployment status is separate."
                } else { Add-Result 'Candidate JAR preservation' 'FAIL' 'Candidate copy SHA-256 did not match the packaged JAR.' }
            } else {
                Add-Result 'Candidate JAR creation' 'UNVERIFIED' 'No candidate build was requested; the verified existing JAR was not copied or replaced.'
            }
            } else { Add-Result 'Packaged JAR metadata' 'FAIL' 'JAR metadata did not match gradle.properties.' }
        } else { Add-Result 'Packaged JAR metadata' 'FAIL' 'Expected packaged JAR was not produced.' }
    } else {
        Add-Result 'Packaged JAR metadata' 'UNVERIFIED' 'Packaging metadata check requires a successful Gradle test/build step.'
    }
} catch {
    $safeMessage = $_.Exception.Message -replace '[\r\n]+', ' '
    Add-Result 'Validation orchestrator' 'FAIL' "Unexpected validation error ($($_.Exception.GetType().Name)): $safeMessage"
} finally {
    $scriptTimer.Stop()
    $finishedAt = [DateTime]::UtcNow
    $counts = @{}
    foreach ($statusName in @('PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE', 'UNVERIFIED', 'UNSUPPORTED')) {
        $counts[$statusName] = @($results | Where-Object status -eq $statusName).Count
    }
    $report = [ordered]@{
        runId = $runId
        mode = $Mode
        candidateBuildRequested = [bool]$BuildCandidate
        forcedTestExecution = [bool]$ForceTestExecution
        startedAtUtc = $startedAt.ToString('o')
        finishedAtUtc = $finishedAt.ToString('o')
        durationSeconds = [Math]::Round($scriptTimer.Elapsed.TotalSeconds, 2)
        counts = $counts
        results = @($results)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportJson -Encoding UTF8
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Full validation report')
    $lines.Add('')
    $lines.Add("- Mode: $Mode")
    $lines.Add("- Started: $($startedAt.ToString('u'))")
    $lines.Add("- Finished: $($finishedAt.ToString('u'))")
    $lines.Add("- Duration: $([Math]::Round($scriptTimer.Elapsed.TotalSeconds, 2)) seconds")
    $lines.Add("- Results: PASS $($counts.PASS), FAIL $($counts.FAIL), BLOCKED $($counts.BLOCKED), INCONCLUSIVE $($counts.INCONCLUSIVE), UNVERIFIED $($counts.UNVERIFIED), UNSUPPORTED $($counts.UNSUPPORTED)")
    $lines.Add('')
    $lines.Add('| Check | Result | Evidence |')
    $lines.Add('|---|---|---|')
    foreach ($item in $results) {
        $safeEvidence = ($item.evidence -replace '\|', '\|' -replace '[\r\n]+', ' ')
        $lines.Add("| $($item.name) | $($item.status) | $safeEvidence |")
    }
    $lines.Add('')
    $lines.Add("JSON report: $(Split-Path -Leaf $reportJson)")
    $lines | Set-Content -LiteralPath $reportMarkdown -Encoding UTF8
    Write-Host "Validation reports: $reportMarkdown and $reportJson"
    Write-Host "PASS=$($counts.PASS) FAIL=$($counts.FAIL) BLOCKED=$($counts.BLOCKED) INCONCLUSIVE=$($counts.INCONCLUSIVE) UNVERIFIED=$($counts.UNVERIFIED) UNSUPPORTED=$($counts.UNSUPPORTED)"
}

if (@($results | Where-Object status -eq 'FAIL').Count -gt 0) { exit 1 }
exit 0
