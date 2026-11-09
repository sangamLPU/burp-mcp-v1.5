$ErrorActionPreference = 'Stop'

$proxyHost = '127.0.0.1'
$proxyPort = 8080
$targetUri = [Uri]'http://127.0.0.1:8000/test-upload'
$uploadFilePath = Join-Path $PSScriptRoot '..\build\burp-mcp-upload-test.txt'
$uploadFilename = 'burp_mcp_test.txt'
$expectedFileText = 'Burp MCP multipart upload test data only.'
$expectedFileBytes = [System.Text.Encoding]::ASCII.GetBytes($expectedFileText)
if (-not (Test-Path -LiteralPath $uploadFilePath -PathType Leaf)) {
    throw 'The generated harmless test file is missing; refusing to send.'
}
$uploadFileBytes = [System.IO.File]::ReadAllBytes($uploadFilePath)
$fileBytesMatchExpected = ($uploadFileBytes.Length -eq $expectedFileBytes.Length)
if ($fileBytesMatchExpected) {
    for ($index = 0; $index -lt $expectedFileBytes.Length; $index++) {
        if ($uploadFileBytes[$index] -ne $expectedFileBytes[$index]) {
            $fileBytesMatchExpected = $false
            break
        }
    }
}
if (-not $fileBytesMatchExpected) {
    throw 'The test file differs from the generated test fixture; refusing to send.'
}

$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $localFileSha256 = ([BitConverter]::ToString($sha.ComputeHash($uploadFileBytes)) -replace '-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}

$boundary = '----BurpMCPPhase2_' + [Guid]::NewGuid().ToString('N')
$crlf = [string]([char]13) + [char]10
function Write-AsciiText {
    param(
        [System.IO.MemoryStream]$Stream,
        [string]$Text
    )
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
}

$bodyStream = [System.IO.MemoryStream]::new()
$textFields = @(
    [pscustomobject]@{ Name = 'mcp_test'; Value = 'original' }
    [pscustomobject]@{ Name = 'name'; Value = 'test' }
    [pscustomobject]@{ Name = 'note'; Value = 'keep-this' }
)
foreach ($field in $textFields) {
    Write-AsciiText -Stream $bodyStream -Text "--$boundary$crlf"
    $disposition = 'Content-Disposition: form-data; name="{0}"{1}{1}' -f $field.Name, $crlf
    Write-AsciiText -Stream $bodyStream -Text $disposition
    Write-AsciiText -Stream $bodyStream -Text $field.Value
    Write-AsciiText -Stream $bodyStream -Text $crlf
}
Write-AsciiText -Stream $bodyStream -Text "--$boundary$crlf"
$fileDisposition = 'Content-Disposition: form-data; name="file"; filename="{0}"{1}' -f $uploadFilename, $crlf
Write-AsciiText -Stream $bodyStream -Text $fileDisposition
Write-AsciiText -Stream $bodyStream -Text "Content-Type: text/plain$crlf$crlf"
$bodyStream.Write($uploadFileBytes, 0, $uploadFileBytes.Length)
Write-AsciiText -Stream $bodyStream -Text "$crlf--$boundary--$crlf"
$requestBodyBytes = $bodyStream.ToArray()
$bodyStream.Dispose()
if ($requestBodyBytes.Length -le $uploadFileBytes.Length) {
    throw 'Multipart framing check failed before connect; refusing to send.'
}

$requestHeaders = @(
    "POST $($targetUri.AbsoluteUri) HTTP/1.1"
    'Host: 127.0.0.1:8000'
    "Content-Type: multipart/form-data; boundary=$boundary"
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
if ($requestBytes.Length -ne $requestHeaderBytes.Length + $requestBodyBytes.Length) {
    throw 'Request Content-Length framing check failed before connect; refusing to send.'
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
        $serverResult.ServerVerified -eq $true -and
        $serverResult.ContentTypeVerified -eq $true -and
        $serverResult.BoundaryVerified -eq $true -and
        $serverResult.PartCount -eq 4 -and
        $serverResult.McpTestModified -eq $true -and
        $serverResult.NameFieldPreserved -eq $true -and
        $serverResult.NoteFieldPreserved -eq $true -and
        $serverResult.FilenameVerified -eq $true -and
        $serverResult.FileContentTypeVerified -eq $true -and
        $serverResult.FileBytesMatch -eq $true -and
        $serverResult.FileByteLength -eq $uploadFileBytes.Length -and
        $serverResult.FileSha256 -eq $localFileSha256 -and
        $serverResult.RequestContentLength -eq $requestBodyBytes.Length -and
        $serverResult.RequestBodyByteLength -eq $requestBodyBytes.Length -and
        $serverResult.RequestContentLengthMatchesBody -eq $true
    )
    $passed = ($statusCode -eq 200 -and $actualResponseLength -eq $expectedResponseLength -and $serverVerified)
    [pscustomobject]@{
        Result = if ($passed) { 'PASS' } else { 'FAIL' }
        Target = $targetUri.AbsoluteUri
        Proxy = "$($proxyHost):$proxyPort"
        HttpStatus = $statusCode
        ResponseContentLength = $expectedResponseLength
        ResponseBodyBytesReceived = $actualResponseLength
        RequestContentLength = $requestBodyBytes.Length
        RequestBodyBytesReceivedByServer = $serverResult.RequestBodyByteLength
        RequestContentLengthMatchesBody = $serverResult.RequestContentLengthMatchesBody
        MultipartContentTypeVerified = $serverResult.ContentTypeVerified
        MultipartBoundaryVerified = $serverResult.BoundaryVerified
        MultipartPartCount = $serverResult.PartCount
        McpTestModified = $serverResult.McpTestModified
        NameFieldPreserved = $serverResult.NameFieldPreserved
        NoteFieldPreserved = $serverResult.NoteFieldPreserved
        UploadFilename = $uploadFilename
        UploadFileBytesMatch = $serverResult.FileBytesMatch
        UploadFileByteLength = $serverResult.FileByteLength
        UploadFileSha256 = $serverResult.FileSha256
        ServerVerified = $serverResult.ServerVerified
    } | Format-List

    if (-not $passed) {
        throw 'Phase 2 server/client verification failed. This script sends one request only; inspect results before deciding any further action.'
    }
} finally {
    $responseMemory.Dispose()
    $client.Dispose()
}
