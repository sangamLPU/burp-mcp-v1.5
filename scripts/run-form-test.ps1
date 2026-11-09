$ErrorActionPreference = 'Stop'

$proxyHost = '127.0.0.1'
$proxyPort = 8080
$targetUri = [Uri]'http://127.0.0.1:8000/test-form'
$requestBody = 'name=test&mcp_test=original'
$requestBodyBytes = [System.Text.Encoding]::ASCII.GetBytes($requestBody)
if ($requestBodyBytes.Length -ne 27) {
    throw 'Unexpected fixed test-body length; refusing to send.'
}

$crlf = [string]([char]13) + [char]10
$requestHeaders = @(
    "POST $($targetUri.AbsoluteUri) HTTP/1.1"
    'Host: 127.0.0.1:8000'
    'Content-Type: application/x-www-form-urlencoded'
    "Content-Length: $($requestBodyBytes.Length)"
    'Connection: close'
    ''
    ''
) -join $crlf
$requestHeaderBytes = [System.Text.Encoding]::ASCII.GetBytes($requestHeaders)
$requestMemory = [System.IO.MemoryStream]::new()
$requestMemory.Write($requestHeaderBytes, 0, $requestHeaderBytes.Length)
$requestMemory.Write($requestBodyBytes, 0, $requestBodyBytes.Length)
$requestBytes = $requestMemory.ToArray()
$requestMemory.Dispose()
if ($requestBytes.Length -ne $requestHeaderBytes.Length + 27) {
    throw 'Request framing check failed before connect; refusing to send.'
}

$client = [System.Net.Sockets.TcpClient]::new()
$client.SendTimeout = 10000
$client.ReceiveTimeout = 125000
$responseMemory = [System.IO.MemoryStream]::new()
try {
    # The only network connection is to the local Burp Proxy listener.
    $client.Connect($proxyHost, $proxyPort)
    $stream = $client.GetStream()
    $stream.Write($requestBytes, 0, $requestBytes.Length)
    $stream.Flush()

    $buffer = New-Object byte[] 4096
    $headerLength = -1
    $expectedResponseLength = -1
    $doubleCrlf = $crlf + $crlf
    while ($true) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }
        $responseMemory.Write($buffer, 0, $read)
        $responseBytes = $responseMemory.ToArray()

        if ($headerLength -lt 0) {
            $candidateText = [System.Text.Encoding]::ASCII.GetString($responseBytes)
            $separatorIndex = $candidateText.IndexOf($doubleCrlf, [System.StringComparison]::Ordinal)
            if ($separatorIndex -ge 0) {
                $headerLength = $separatorIndex + $doubleCrlf.Length
                $headerBlock = [System.Text.Encoding]::ASCII.GetString($responseBytes, 0, $headerLength)
                if ([regex]::IsMatch($headerBlock, '(?im)^Transfer-Encoding:\s*chunked\s*$')) {
                    throw 'Unexpected chunked response framing; no PASS reported.'
                }
                $lengthMatch = [regex]::Match($headerBlock, '(?im)^Content-Length:\s*(\d+)\s*$')
                if (-not $lengthMatch.Success) {
                    throw 'Response Content-Length is missing; no PASS reported.'
                }
                $expectedResponseLength = [int]$lengthMatch.Groups[1].Value
            }
        }

        if ($headerLength -ge 0 -and $expectedResponseLength -ge 0 -and
            $responseBytes.Length -ge $headerLength + $expectedResponseLength) {
            break
        }
    }

    $responseBytes = $responseMemory.ToArray()
    if ($headerLength -lt 0 -or $expectedResponseLength -lt 0) {
        throw 'Incomplete HTTP response; no PASS reported. Do not rerun automatically.'
    }
    $actualResponseLength = $responseBytes.Length - $headerLength
    if ($actualResponseLength -ne $expectedResponseLength) {
        throw "Response Content-Length mismatch ($expectedResponseLength declared, $actualResponseLength received); no PASS reported."
    }

    $headerBlock = [System.Text.Encoding]::ASCII.GetString($responseBytes, 0, $headerLength)
    $firstLineEnd = $headerBlock.IndexOf($crlf, [System.StringComparison]::Ordinal)
    if ($firstLineEnd -lt 0) { throw 'Malformed HTTP response status line; no PASS reported.' }
    $statusLine = $headerBlock.Substring(0, $firstLineEnd)
    $statusMatch = [regex]::Match($statusLine, '^HTTP/\d\.\d\s+(?<code>\d{3})')
    if (-not $statusMatch.Success) { throw 'Malformed HTTP response status; no PASS reported.' }
    $statusCode = [int]$statusMatch.Groups['code'].Value

    $responseBody = [System.Text.Encoding]::UTF8.GetString(
        $responseBytes,
        $headerLength,
        $actualResponseLength
    )
    $serverResult = ConvertFrom-Json -InputObject $responseBody -ErrorAction Stop
    $serverVerified = (
        $serverResult.serverVerified -eq $true -and
        $serverResult.method -eq 'POST' -and
        $serverResult.path -eq '/test-form' -and
        $serverResult.nameFieldUnchanged -eq $true -and
        $serverResult.mcpTestModified -eq $true -and
        $serverResult.formFieldCount -eq 2 -and
        $serverResult.formContentTypeVerified -eq $true -and
        $serverResult.requestContentLengthMatchesBody -eq $true
    )
    $passed = ($statusCode -eq 200 -and $actualResponseLength -eq $expectedResponseLength -and $serverVerified)
    [pscustomobject]@{
        Result = if ($passed) { 'PASS' } else { 'FAIL' }
        Target = $targetUri.AbsoluteUri
        Proxy = "$($proxyHost):$proxyPort"
        HttpStatus = $statusCode
        ResponseContentLength = $expectedResponseLength
        ResponseBodyBytesReceived = $actualResponseLength
        RequestContentLength = $serverResult.requestContentLength
        RequestBodyBytesReceivedByServer = $serverResult.requestBodyByteLength
        RequestContentLengthMatchesBody = $serverResult.requestContentLengthMatchesBody
        FormContentTypeVerified = $serverResult.formContentTypeVerified
        FormFieldCount = $serverResult.formFieldCount
        NameFieldUnchanged = $serverResult.nameFieldUnchanged
        McpTestModified = $serverResult.mcpTestModified
        ServerVerified = $serverResult.serverVerified
    } | Format-List

    if (-not $passed) {
        throw 'Phase 1 server/client verification failed. This script sends one request only; inspect results before deciding any further action.'
    }
} finally {
    $responseMemory.Dispose()
    $client.Dispose()
}
