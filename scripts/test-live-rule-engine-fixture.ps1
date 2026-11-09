$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$serverScript = Join-Path $PSScriptRoot 'local-test-server.ps1'
$logPath = Join-Path $env:TEMP ("burp-rule-fixture-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
$stdoutPath = Join-Path $env:TEMP ("burp-rule-fixture-{0}.out.log" -f [guid]::NewGuid().ToString('N'))
$stderrPath = Join-Path $env:TEMP ("burp-rule-fixture-{0}.err.log" -f [guid]::NewGuid().ToString('N'))
$serverProcess = $null
$client = $null

try {
    if (@(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'The fixture test will not replace an existing listener on 127.0.0.1:8000.'
    }
    $shellPath = (Get-Process -Id $PID).Path
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $serverScript,
        '-LogPath', $logPath, '-MaxRequests', '2', '-MaxBodyBytes', '65536',
        '-RequestTimeoutSeconds', '5', '-MaxRunSeconds', '60', '-RuleEngineTestMode')
    $serverProcess = Start-Process -FilePath $shellPath -ArgumentList $args -WorkingDirectory $repoRoot `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and
        @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue).Count -eq 0) {
        if ($serverProcess.HasExited) { throw 'Rule test fixture exited before listening.' }
        Start-Sleep -Milliseconds 100
    }
    if (@(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue).Count -eq 0) {
        throw 'Rule test fixture did not bind to 127.0.0.1:8000.'
    }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $body = '{"enabled":true,"name":"original","mcp_test":"after","marker":"preserve","case":"fixture-one","nested":{"keep":17}}'
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, 'http://127.0.0.1:8000/test-post')
    $request.Content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, 'application/json')
    $request.Headers.Add('X-MCP-Test-ID', 'fixture-one')
    $request.Headers.Add('X-MCP-Rule-Test', 'active')
    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    $responseJson = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
    if ([int]$response.StatusCode -ne 200 -or $responseJson.enabled -ne $false -or
        $responseJson.name -ne 'original' -or $responseJson.marker -ne 'preserve' -or $responseJson.nested.keep -ne 17) {
        throw 'Rule test fixture did not return enabled=false while preserving the JSON fields.'
    }
    $request.Dispose(); $response.Dispose()

    $pauseRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, 'http://127.0.0.1:8000/test-post')
    $pauseRequest.Content = [System.Net.Http.StringContent]::new(
        '{"enabled":false,"name":"original","mcp_test":"after","marker":"preserve","case":"fixture-pause","nested":{"keep":17}}',
        [System.Text.Encoding]::UTF8, 'application/json')
    $pauseRequest.Headers.Add('X-MCP-Test-ID', 'fixture-pause')
    $pauseRequest.Headers.Add('X-MCP-Pause-Forward', 'active')
    $pauseResponse = $client.SendAsync($pauseRequest).GetAwaiter().GetResult()
    $pauseJson = $pauseResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
    if ([int]$pauseResponse.StatusCode -ne 200 -or $pauseJson.enabled -ne $false -or
        $pauseResponse.Headers.GetValues('X-MCP-Pause-Forward') -notcontains 'active') {
        throw 'Pause pass-through fixture response did not preserve enabled=false and its marker header.'
    }
    $pauseRequest.Dispose(); $pauseResponse.Dispose()

    $records = @([IO.File]::ReadAllLines($logPath) | ForEach-Object { $_ | ConvertFrom-Json })
    if ($records.Count -ne 2 -or $records[0].ruleTestId -ne 'fixture-one' -or
        $records[0].postEnabled -ne $true -or -not $records[0].ruleTestHeaderObserved -or
        $records[0].pauseHeaderObserved -or $records[1].ruleTestId -ne 'fixture-pause' -or
        $records[1].postEnabled -ne $false -or -not $records[1].pauseHeaderObserved -or
        -not $records[0].bodyFramingVerified -or -not $records[1].bodyFramingVerified) {
        throw 'Rule test origin evidence did not confirm exact IDs, enabled values, headers, and framing.'
    }
    Write-Output 'PASS: offline rule fixture returned enabled=false, preserved JSON fields, observed request headers, and recorded exact origin framing.'
} finally {
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $serverProcess) {
        $serverProcess.Refresh()
        if (-not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
    }
    foreach ($path in @($logPath, $stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $path) { [IO.File]::Delete($path) }
    }
}
