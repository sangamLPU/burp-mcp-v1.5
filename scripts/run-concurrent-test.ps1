$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'concurrent-test-validation.ps1')

$proxyHost = '127.0.0.1'
$proxyPort = 8080
$targetHost = '127.0.0.1'
$targetPort = 8000
$crlf = [string]([char]13) + [char]10
$idA = 'phase3-A-' + [Guid]::NewGuid().ToString('N')
$idB = 'phase3-B-' + [Guid]::NewGuid().ToString('N')
if ($idA -eq $idB) { throw 'Generated test identifiers collided; refusing to send.' }

$bodyA = "test_id=$idA&mcp_test=alpha&name=case-A&marker=keep-A"
$bodyB = "test_id=$idB&mcp_test=beta&name=case-B&marker=keep-B"

function New-LoopbackRequestBytes {
    param(
        [string]$Path,
        [string]$Body,
        [string]$Crlf
    )
    $bodyBytes = [System.Text.Encoding]::ASCII.GetBytes($Body)
    $headerText = @(
        "POST http://127.0.0.1:8000$Path HTTP/1.1"
        'Host: 127.0.0.1:8000'
        'Content-Type: application/x-www-form-urlencoded'
        "Content-Length: $($bodyBytes.Length)"
        'Connection: close'
        ''
        ''
    ) -join $Crlf
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headerText)
    $memory = [System.IO.MemoryStream]::new()
    $memory.Write($headerBytes, 0, $headerBytes.Length)
    $memory.Write($bodyBytes, 0, $bodyBytes.Length)
    $requestBytes = $memory.ToArray()
    $memory.Dispose()
    if ($requestBytes.Length -ne $headerBytes.Length + $bodyBytes.Length) {
        throw "Request framing check failed for $Path; refusing to send."
    }
    [pscustomobject]@{
        Bytes = $requestBytes
        BodyLength = $bodyBytes.Length
    }
}

function Read-LoopbackResponse {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [string]$Crlf,
        [string]$Label
    )
    $memory = [System.IO.MemoryStream]::new()
    try {
        $buffer = New-Object byte[] 4096
        $headerLength = -1
        $expectedLength = -1
        $doubleCrlf = $Crlf + $Crlf
        while ($true) {
            $read = $Stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $memory.Write($buffer, 0, $read)
            $received = $memory.ToArray()
            if ($headerLength -lt 0) {
                $candidate = [System.Text.Encoding]::ASCII.GetString($received)
                $separator = $candidate.IndexOf($doubleCrlf, [System.StringComparison]::Ordinal)
                if ($separator -ge 0) {
                    $headerLength = $separator + $doubleCrlf.Length
                    $headers = [System.Text.Encoding]::ASCII.GetString($received, 0, $headerLength)
                    if ([regex]::IsMatch($headers, '(?im)^Transfer-Encoding:\s*chunked\s*$')) {
                        throw "$Label response used chunked framing; no PASS reported."
                    }
                    $match = [regex]::Match($headers, '(?im)^Content-Length:\s*(\d+)\s*$')
                    if (-not $match.Success) {
                        throw "$Label response Content-Length is missing; no PASS reported."
                    }
                    $expectedLength = [int]$match.Groups[1].Value
                }
            }
            if ($headerLength -ge 0 -and $expectedLength -ge 0 -and
                $received.Length -ge $headerLength + $expectedLength) {
                break
            }
        }

        $received = $memory.ToArray()
        if ($headerLength -lt 0 -or $expectedLength -lt 0) {
            throw "$Label response was incomplete or expired; no retry will be made."
        }
        $actualLength = $received.Length - $headerLength
        if ($actualLength -ne $expectedLength) {
            throw "$Label response framing mismatch ($expectedLength declared, $actualLength received); no retry will be made."
        }
        $headers = [System.Text.Encoding]::ASCII.GetString($received, 0, $headerLength)
        $lineEnd = $headers.IndexOf($Crlf, [System.StringComparison]::Ordinal)
        if ($lineEnd -lt 0) { throw "$Label response status line is malformed; no PASS reported." }
        $statusLine = $headers.Substring(0, $lineEnd)
        $statusMatch = [regex]::Match($statusLine, '^HTTP/\d\.\d\s+(?<code>\d{3})')
        if (-not $statusMatch.Success) { throw "$Label response status is malformed; no PASS reported." }
        $statusCode = [int]$statusMatch.Groups['code'].Value
        $bodyText = [System.Text.Encoding]::UTF8.GetString($received, $headerLength, $actualLength)
        $json = ConvertFrom-Json -InputObject $bodyText -ErrorAction Stop
        [pscustomobject]@{
            StatusCode = $statusCode
            ContentLength = $expectedLength
            BytesReceived = $actualLength
            Json = $json
        }
    } finally {
        $memory.Dispose()
    }
}

$requestA = New-LoopbackRequestBytes -Path '/test-concurrent-a' -Body $bodyA -Crlf $crlf
$requestB = New-LoopbackRequestBytes -Path '/test-concurrent-b' -Body $bodyB -Crlf $crlf
$clientA = [System.Net.Sockets.TcpClient]::new()
$clientB = [System.Net.Sockets.TcpClient]::new()
$clientA.SendTimeout = 10000
$clientB.SendTimeout = 10000
$clientA.ReceiveTimeout = 125000
$clientB.ReceiveTimeout = 125000
try {
    # Establish both local Proxy connections before sending either request.
    $connectA = $clientA.ConnectAsync($proxyHost, $proxyPort)
    $connectB = $clientB.ConnectAsync($proxyHost, $proxyPort)
    $connectedA = $connectA.Wait(10000)
    $connectedB = $connectB.Wait(10000)
    if (-not $connectedA -or -not $connectedB) {
        throw 'Could not connect both clients to the local Burp Proxy; no requests will be retried.'
    }

    $streamA = $clientA.GetStream()
    $streamB = $clientB.GetStream()
    # Send both requests before reading either response, leaving both independently pending in Burp.
    $streamA.Write($requestA.Bytes, 0, $requestA.Bytes.Length)
    $streamA.Flush()
    $streamB.Write($requestB.Bytes, 0, $requestB.Bytes.Length)
    $streamB.Flush()

    $responseA = Read-LoopbackResponse -Stream $streamA -Crlf $crlf -Label 'A'
    $responseB = Read-LoopbackResponse -Stream $streamB -Crlf $crlf -Label 'B'

    $serverA = $responseA.Json
    $serverB = $responseB.Json
    $validation = Test-ConcurrentRunnerResult -ResponseA $responseA -ResponseB $responseB -TestIdA $idA -TestIdB $idB
    $passed = $validation.Passed
    [pscustomobject]@{
        Result = if ($passed) { 'PASS' } else { 'FAIL' }
        UniqueTestIds = ($idA -ne $idB)
        A_TestId = $idA
        A_ServerTestId = $serverA.TestId
        A_HttpStatus = $responseA.StatusCode
        A_RequestContentLength = $serverA.RequestContentLength
        A_RequestBodyBytesReceived = $serverA.RequestBodyByteLength
        A_ResponseContentLength = $responseA.ContentLength
        A_ResponseBytesReceived = $responseA.BytesReceived
        A_ExpectedEditedValue = 'alpha-modified'
        A_McpTestModified = $serverA.McpTestModified
        A_RequestFramingVerified = $validation.Checks.A_RequestFraming
        A_NamePreserved = $serverA.NameFieldPreserved
        A_MarkerPreserved = $serverA.MarkerFieldPreserved
        A_ServerVerified = $serverA.ServerVerified
        B_TestId = $idB
        B_ServerTestId = $serverB.TestId
        B_HttpStatus = $responseB.StatusCode
        B_RequestContentLength = $serverB.RequestContentLength
        B_RequestBodyBytesReceived = $serverB.RequestBodyByteLength
        B_ResponseContentLength = $responseB.ContentLength
        B_ResponseBytesReceived = $responseB.BytesReceived
        B_ExpectedEditedValue = 'beta-modified'
        B_McpTestModified = $serverB.McpTestModified
        B_RequestFramingVerified = $validation.Checks.B_RequestFraming
        B_NamePreserved = $serverB.NameFieldPreserved
        B_MarkerPreserved = $serverB.MarkerFieldPreserved
        B_ServerVerified = $serverB.ServerVerified
        FailedConditions = ($validation.FailedConditions -join ', ')
        AutomaticRetries = $false
    } | Format-List

    if (-not $passed) {
        throw "Concurrent server/client verification failed: $($validation.FailedConditions -join ', '). This runner sends exactly two requests and will not retry either one."
    }
} finally {
    $clientA.Dispose()
    $clientB.Dispose()
}
