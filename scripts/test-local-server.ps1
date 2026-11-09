$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$serverScript = Join-Path $PSScriptRoot 'local-test-server.ps1'
$validationDir = Join-Path $repoRoot 'build\validation'
$null = New-Item -ItemType Directory -Force -Path $validationDir
$logPath = Join-Path $validationDir ("local-server-{0}.jsonl" -f [Guid]::NewGuid().ToString('N'))
$stdoutPath = Join-Path $validationDir ("local-server-{0}.out.log" -f [Guid]::NewGuid().ToString('N'))
$stderrPath = Join-Path $validationDir ("local-server-{0}.err.log" -f [Guid]::NewGuid().ToString('N'))
$results = [System.Collections.Generic.List[object]]::new()
$serverProcess = $null
$client = $null

function Add-LocalTestResult {
    param([string]$Name, [scriptblock]$Action)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $results.Add([pscustomobject]@{ Name = $Name; Status = 'PASS'; DurationMs = $timer.ElapsedMilliseconds })
    } catch {
        $innerType = if ($null -ne $_.Exception.InnerException) { $_.Exception.InnerException.GetType().Name } else { $_.Exception.GetType().Name }
        $safeError = if ($_.Exception -is [System.Management.Automation.RuntimeException]) { $_.Exception.Message } else { $innerType }
        $results.Add([pscustomobject]@{ Name = $Name; Status = 'FAIL'; DurationMs = $timer.ElapsedMilliseconds; Error = $safeError })
    }
}

function Invoke-LocalHttp {
    param(
        [Parameter(Mandatory = $true)] [string]$Method,
        [Parameter(Mandatory = $true)] [string]$Path,
        [AllowNull()] [byte[]]$Body = $null,
        [string]$ContentType = 'application/octet-stream',
        [string]$Cookie = $null,
        [string]$TestId = $null
    )
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method), "http://127.0.0.1:8000$Path"
    )
    $cancel = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(6))
    try {
        if ($null -ne $Body) {
            $content = [System.Net.Http.ByteArrayContent]::new($Body)
            $mediaType = ($ContentType -split ';', 2)[0].Trim()
            $contentTypeHeader = [System.Net.Http.Headers.MediaTypeHeaderValue]::new($mediaType)
            if ($ContentType -match '(?i)(?:^|;)\s*charset=(?<charset>[^;\s]+)') {
                $contentTypeHeader.CharSet = $Matches['charset'].Trim('"')
            }
            $content.Headers.ContentType = $contentTypeHeader
            $request.Content = $content
        }
        if ($Cookie) { $request.Headers.TryAddWithoutValidation('Cookie', $Cookie) | Out-Null }
        if ($TestId) { $request.Headers.TryAddWithoutValidation('X-MCP-Test-ID', $TestId) | Out-Null }
        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseContentRead, $cancel.Token).GetAwaiter().GetResult()
        try {
            $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                BodyBytes = $bytes
                BodyText = $text
                Headers = $response.Headers
                ContentHeaders = $response.Content.Headers
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $cancel.Dispose()
        $request.Dispose()
    }
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Invoke-RawHttp {
    param([byte[]]$RequestBytes, [switch]$ShutdownSend)
    $tcp = [System.Net.Sockets.TcpClient]::new()
    $memory = [System.IO.MemoryStream]::new()
    try {
        $tcp.SendTimeout = 2000
        $tcp.ReceiveTimeout = 3000
        $tcp.Connect('127.0.0.1', 8000)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 3000
        $stream.Write($RequestBytes, 0, $RequestBytes.Length)
        $stream.Flush()
        if ($ShutdownSend) { $tcp.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send) }
        $buffer = New-Object byte[] 4096
        while ($memory.Length -le 65536) {
            try { $read = $stream.Read($buffer, 0, $buffer.Length) }
            catch [System.IO.IOException] { break }
            if ($read -le 0) { break }
            $memory.Write($buffer, 0, $read)
        }
        $received = $memory.ToArray()
        $text = [System.Text.Encoding]::ASCII.GetString($received)
        $statusLine = ($text -split "`r`n", 2)[0]
        $status = $null
        if ($statusLine -match '^HTTP/1\.[01] (?<code>[0-9]{3})') { $status = [int]$Matches['code'] }
        [pscustomobject]@{ StatusCode = $status; ResponseBytes = $received; StatusLine = $statusLine }
    } finally {
        $memory.Dispose()
        $tcp.Dispose()
    }
}

function New-AsciiRequest {
    param([string]$Text)
    [System.Text.Encoding]::ASCII.GetBytes($Text)
}

try {
    $occupied = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue)
    if ($occupied.Count -gt 0) { throw '127.0.0.1:8000 is already in use; the existing process was left untouched.' }

    $shellPath = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($shellPath)) { throw 'Could not identify the current PowerShell executable.' }
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $serverScript,
        '-LogPath', $logPath, '-MaxRequests', '40', '-MaxBodyBytes', '1048576',
        '-RequestTimeoutSeconds', '8', '-MaxRunSeconds', '120', '-TimeoutDelayMilliseconds', '100'
    )
    $serverProcess = Start-Process -FilePath $shellPath -ArgumentList $arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $listenDeadline = [DateTime]::UtcNow.AddSeconds(10)
    $isListening = $false
    while ([DateTime]::UtcNow -lt $listenDeadline) {
        if ($serverProcess.HasExited) { throw 'Local test server exited before binding to 127.0.0.1:8000.' }
        $isListening = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue).Count -gt 0
        if ($isListening) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $isListening) { throw 'Local test server did not bind within 10 seconds.' }

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(7)
    $crlf = "`r`n"
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $unicodeBytes = $utf8.GetBytes('Synthetic UTF-8: café – 東京 🌱')
    $binaryBytes = [byte[]]@(0, 1, 127, 128, 255, 42)
    $largeBytes = New-Object byte[] 65536
    for ($i = 0; $i -lt $largeBytes.Length; $i++) { $largeBytes[$i] = [byte]($i % 256) }

    Add-LocalTestResult 'Premature request EOF is rejected' {
        $partialCrlf = ([string][char]13) + [char]10
        $partialText = "POST /test-post HTTP/1.1$partialCrlf" +
            "Host: 127.0.0.1:8000$partialCrlf" +
            "Content-Length: 5$partialCrlf" +
            "Connection: close$partialCrlf$partialCrlf" + 'ab'
        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($partialText)
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $memory = [System.IO.MemoryStream]::new()
        try {
            $tcp.Connect('127.0.0.1', 8000)
            $stream = $tcp.GetStream()
            $stream.ReadTimeout = 3000
            $stream.Write($requestBytes, 0, $requestBytes.Length)
            $stream.Flush()
            $tcp.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
            $buffer = New-Object byte[] 4096
            while ($memory.Length -le 65536) {
                try { $read = $stream.Read($buffer, 0, $buffer.Length) }
                catch [System.IO.IOException] { break }
                if ($read -le 0) { break }
                $memory.Write($buffer, 0, $read)
            }
            $responseText = [System.Text.Encoding]::ASCII.GetString($memory.ToArray())
            $statusLine = ($responseText -split [regex]::Escape($partialCrlf), 2)[0]
            if ($statusLine -notmatch '^HTTP/1\.[01] 400\b') {
                throw "Premature request body EOF was not rejected; responseBytes=$($memory.Length)."
            }
        } finally {
            $memory.Dispose()
            $tcp.Dispose()
        }
    }

    Add-LocalTestResult 'GET /live-check' {
        $r = Invoke-LocalHttp GET '/live-check'
        if ($r.StatusCode -ne 200 -or $r.BodyText -ne 'Burp MCP local test endpoint') { throw 'Unexpected local health response.' }
    }
    Add-LocalTestResult 'GET /test-html' {
        $r = Invoke-LocalHttp GET '/test-html'
        if ($r.StatusCode -ne 200 -or $r.BodyText -notmatch '<h1>Original Page</h1>') { throw 'HTML fixture mismatch.' }
    }
    Add-LocalTestResult 'POST /test-post JSON' {
        $body = $utf8.GetBytes('{"name":"original","mcp_test":"after"}')
        $r = Invoke-LocalHttp POST '/test-post' $body 'application/json; charset=utf-8'
        if ($r.StatusCode -ne 200 -or $r.BodyBytes.Length -ne $body.Length -or $r.BodyText -ne $utf8.GetString($body)) { throw 'JSON byte-preserving echo failed.' }
    }
    Add-LocalTestResult 'POST /test-form URL-encoded' {
        $body = $utf8.GetBytes('mcp_test=modified&name=test')
        $r = Invoke-LocalHttp POST '/test-form' $body 'application/x-www-form-urlencoded; charset=utf-8'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or -not $json.serverVerified -or $json.requestBodyByteLength -ne $body.Length) { throw 'Form verification or framing failed.' }
    }
    Add-LocalTestResult 'POST /test-upload multipart integrity' {
        $multipart = [System.Net.Http.MultipartFormDataContent]::new()
        try {
            $multipart.Add([System.Net.Http.StringContent]::new('modified', $utf8), 'mcp_test')
            $multipart.Add([System.Net.Http.StringContent]::new('test', $utf8), 'name')
            $multipart.Add([System.Net.Http.StringContent]::new('keep-this', $utf8), 'note')
            $fileBytes = [System.Text.Encoding]::ASCII.GetBytes('Burp MCP multipart upload test data only.')
            $file = [System.Net.Http.ByteArrayContent]::new($fileBytes)
            $file.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('text/plain')
            $multipart.Add($file, 'file', 'burp_mcp_test.txt')
            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, 'http://127.0.0.1:8000/test-upload')
            $request.Content = $multipart
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            try {
                $jsonText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $json = $jsonText | ConvertFrom-Json
                $expectedHash = Get-Sha256Hex $fileBytes
                if ([int]$response.StatusCode -ne 200 -or -not $json.serverVerified -or $json.fileSha256 -ne $expectedHash -or -not $json.fileBytesMatch) {
                    throw 'Multipart boundary, fields, framing, or file integrity failed.'
                }
            } finally { $response.Dispose(); $request.Dispose() }
        } finally { $multipart.Dispose() }
    }
    Add-LocalTestResult 'GET /test-cancel identity' {
        $id = 'phase4a-' + [Guid]::NewGuid().ToString('N')
        $r = Invoke-LocalHttp GET '/test-cancel' $null 'application/octet-stream' -TestId $id
        if ($r.StatusCode -ne 200) { throw 'Cancellation fixture returned a non-200 response.' }
    }
    Add-LocalTestResult 'GET /test-timeout bounded delay' {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-LocalHttp GET '/test-timeout?delayMs=100'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or $json.delayMilliseconds -ne 100 -or $watch.Elapsed.TotalSeconds -gt 5) { throw 'Bounded timeout endpoint failed.' }
    }
    Add-LocalTestResult 'GET /test-session-expiry' {
        $r = Invoke-LocalHttp GET '/test-session-expiry'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or -not $json.serverVerified) { throw 'Session-expiry fixture failed.' }
    }
    Add-LocalTestResult 'POST /test-unicode UTF-8 byte count' {
        $r = Invoke-LocalHttp POST '/test-unicode' $unicodeBytes 'text/plain; charset=utf-8'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or -not $json.utf8Valid -or $json.bodyByteLength -ne $unicodeBytes.Length -or -not $json.contentLengthMatchesBody) { throw 'Unicode byte framing failed.' }
    }
    Add-LocalTestResult 'POST /test-binary byte integrity' {
        $r = Invoke-LocalHttp POST '/test-binary' $binaryBytes 'application/octet-stream'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or $json.bodyByteLength -ne $binaryBytes.Length -or $json.bodySha256 -ne (Get-Sha256Hex $binaryBytes)) { throw 'Binary bytes or SHA-256 did not match.' }
    }
    Add-LocalTestResult 'GET /test-empty' {
        $r = Invoke-LocalHttp GET '/test-empty'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or -not $json.emptyBody) { throw 'Empty body was not preserved.' }
    }
    Add-LocalTestResult 'POST /test-large bounded payload' {
        $r = Invoke-LocalHttp POST '/test-large' $largeBytes 'application/octet-stream'
        $json = $r.BodyText | ConvertFrom-Json
        if ($r.StatusCode -ne 200 -or $json.bodyByteLength -ne $largeBytes.Length -or $json.bodySha256 -ne (Get-Sha256Hex $largeBytes)) { throw 'Bounded large-body integrity failed.' }
    }
    foreach ($method in @('PUT', 'PATCH', 'DELETE')) {
        Add-LocalTestResult "$method /test-method" {
            $body = $utf8.GetBytes("synthetic-$method")
            $r = Invoke-LocalHttp $method '/test-method' $body 'text/plain; charset=utf-8'
            $json = $r.BodyText | ConvertFrom-Json
            if ($r.StatusCode -ne 200 -or $json.method -ne $method -or $json.bodyByteLength -ne $body.Length) { throw 'Method fixture failed.' }
        }
    }
    Add-LocalTestResult 'GET /test-headers' {
        $r = Invoke-LocalHttp GET '/test-headers'
        if ($r.StatusCode -ne 200 -or -not $r.Headers.Contains('X-MCP-Test-Origin')) { throw 'Synthetic response header missing.' }
    }

    Add-LocalTestResult 'Malformed Content-Length is rejected' {
        $request = New-AsciiRequest ("POST /test-post HTTP/1.1${crlf}Host: 127.0.0.1:8000${crlf}Content-Length: invalid${crlf}Connection: close${crlf}${crlf}")
        $r = Invoke-RawHttp $request
        if ($r.StatusCode -ne 400) { throw 'Malformed Content-Length was not rejected with 400.' }
    }
    Add-LocalTestResult 'Oversized body is rejected before read' {
        $request = New-AsciiRequest ("POST /test-large HTTP/1.1${crlf}Host: 127.0.0.1:8000${crlf}Content-Length: 1048577${crlf}Connection: close${crlf}${crlf}")
        $r = Invoke-RawHttp $request
        if ($r.StatusCode -ne 413) { throw 'Oversized body was not rejected with 413.' }
    }
    Add-LocalTestResult 'Conflicting framing is rejected' {
        $request = New-AsciiRequest ("POST /test-post HTTP/1.1${crlf}Host: 127.0.0.1:8000${crlf}Content-Length: 0${crlf}Transfer-Encoding: chunked${crlf}Connection: close${crlf}${crlf}")
        $r = Invoke-RawHttp $request
        if ($r.StatusCode -ne 400) { throw 'Content-Length plus Transfer-Encoding was not rejected.' }
    }
    Add-LocalTestResult 'Chunked request framing is explicit unsupported' {
        $request = New-AsciiRequest ("POST /test-post HTTP/1.1${crlf}Host: 127.0.0.1:8000${crlf}Transfer-Encoding: chunked${crlf}Connection: close${crlf}${crlf}")
        $r = Invoke-RawHttp $request
        if ($r.StatusCode -ne 501) { throw 'Chunked request support was not reported as unsupported.' }
    }
    Add-LocalTestResult 'HTTP/1.1 keep-alive is explicitly closed' {
        $request = New-AsciiRequest ("GET /test-empty HTTP/1.1${crlf}Host: 127.0.0.1:8000${crlf}Connection: keep-alive${crlf}${crlf}")
        $r = Invoke-RawHttp $request
        $headerText = [System.Text.Encoding]::ASCII.GetString($r.ResponseBytes)
        if ($r.StatusCode -ne 200 -or $headerText -notmatch '(?im)^Connection: close\r$') { throw 'Server did not close the keep-alive test connection explicitly.' }
    }

    Add-LocalTestResult 'Origin record count and synthetic request identity' {
        $records = @(Get-Content -LiteralPath $logPath | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
        $cancelRecords = @($records | Where-Object path -eq '/test-cancel')
        if ($records.Count -ne 17) { throw "Expected 17 valid origin deliveries, observed $($records.Count)." }
        if ($cancelRecords.Count -ne 1 -or -not $cancelRecords[0].cancellationRequestVerified) {
            throw 'Cancellation fixture identity was missing, duplicated, or invalid.'
        }
    }

    $logLines = @(Get-Content -LiteralPath $logPath -ErrorAction Stop)
    foreach ($line in $logLines) {
        if ($line -match 'Authorization:|Cookie:|Set-Cookie:|password|secret|requestBody|responseBody') {
            throw 'Persistent local test metadata log contains a forbidden raw-header or body field.'
        }
    }
} finally {
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        $serverProcess.WaitForExit(3000) | Out-Null
    }
}

$results | Format-Table -AutoSize
$results | Where-Object Status -eq 'FAIL' | Format-List
$passed = @($results | Where-Object Status -eq 'PASS').Count
$failed = @($results | Where-Object Status -eq 'FAIL').Count
Write-Output "Local server validation: $passed passed, $failed failed. Metadata log: $logPath"
if ($failed -gt 0) { exit 1 }
