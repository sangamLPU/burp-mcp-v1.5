param(
    [string]$LogPath = (Join-Path $PSScriptRoot '..\build\live-test-server-observations.jsonl'),
    [ValidateRange(1, 1000)] [int]$MaxRequests = 100,
    [ValidateRange(1, 1048576)] [int]$MaxBodyBytes = 1048576,
    [ValidateRange(1, 60)] [int]$RequestTimeoutSeconds = 10,
    [ValidateRange(1, 86400)] [int]$MaxRunSeconds = 1800,
    [ValidateRange(0, 10000)] [int]$TimeoutDelayMilliseconds = 2000,
    [switch]$IdentityFromEnvironment,
    [switch]$RuleEngineTestMode,
    [string]$TestRunId = '',
    [string]$ServerIdentity = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'local-test-method-fixture.ps1')
if ($IdentityFromEnvironment) {
    $TestRunId = [Environment]::GetEnvironmentVariable('BURP_TEST_RUN_ID', 'Process')
    $ServerIdentity = [Environment]::GetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', 'Process')
}
if ([string]::IsNullOrWhiteSpace($TestRunId) -xor [string]::IsNullOrWhiteSpace($ServerIdentity)) {
    throw 'TestRunId and ServerIdentity must either both be supplied or both be empty.'
}
if ($TestRunId -and $TestRunId -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
    throw 'TestRunId is malformed.'
}
if ($ServerIdentity -and $ServerIdentity -notmatch '^[A-Za-z0-9_-]{43}$') {
    throw 'ServerIdentity is malformed.'
}
$LogPath = [System.IO.Path]::GetFullPath($LogPath)
$logDirectory = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

function Read-TestHttpLine {
    param([Parameter(Mandatory = $true)] [System.IO.Stream]$Stream)

    $lineBytes = [System.Collections.Generic.List[byte]]::new()
    while ($lineBytes.Count -le 8192) {
        $next = $Stream.ReadByte()
        if ($next -lt 0) {
            if ($lineBytes.Count -eq 0) { return $null }
            throw 'Unexpected end of stream in HTTP headers.'
        }
        if ($next -eq 10) {
            if ($lineBytes.Count -gt 0 -and $lineBytes[$lineBytes.Count - 1] -eq 13) {
                $lineBytes.RemoveAt($lineBytes.Count - 1)
            }
            return [System.Text.Encoding]::ASCII.GetString($lineBytes.ToArray())
        }
        $lineBytes.Add([byte]$next)
    }
    throw 'HTTP header line exceeds the 8192-byte limit.'
}

function Send-TestHttpResponse {
    param(
        [Parameter(Mandatory = $true)] [System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)] [string]$Status,
        [Parameter(Mandatory = $true)] [byte[]]$BodyBytes,
        [string]$ContentType = 'text/plain; charset=utf-8',
        [string[]]$ExtraHeaders = @()
    )

    $crlf = ([string][char]13) + [char]10
    $headers = [System.Collections.Generic.List[string]]::new()
    $headers.Add("HTTP/1.1 $Status")
    $headers.Add("Content-Type: $ContentType")
    foreach ($header in $ExtraHeaders) { $headers.Add($header) }
    $headers.Add("Content-Length: $($BodyBytes.Length)")
    $headers.Add('Connection: close')
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes(([string]::Join($crlf, $headers.ToArray()) + $crlf + $crlf))
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    if ($BodyBytes.Length -gt 0) { $Stream.Write($BodyBytes, 0, $BodyBytes.Length) }
    $Stream.Flush()
}

function Get-TestSha256 {
    param([AllowNull()] [AllowEmptyCollection()] [byte[]]$Bytes)
    if ($null -eq $Bytes) { $Bytes = [byte[]]@() }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-ConcurrentFormVerification {
    param(
        [string]$Path,
        [string]$ContentTypeHeader,
        [string]$Body,
        [int]$RequestContentLength,
        [int]$BytesRead
    )

    $contentTypeVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ContentTypeHeader)) {
        $mediaType = ($ContentTypeHeader -split ';', 2)[0].Trim()
        $contentTypeVerified = $mediaType -ieq 'application/x-www-form-urlencoded'
    }

    $fields = @{}
    $duplicateFields = $false
    $malformedField = $false
    $pairs = $Body.Split('&')
    foreach ($pair in $pairs) {
        $parts = $pair.Split('=', 2)
        if ($parts.Length -ne 2) {
            $malformedField = $true
            continue
        }
        $key = [Uri]::UnescapeDataString($parts[0].Replace('+', ' '))
        $value = [Uri]::UnescapeDataString($parts[1].Replace('+', ' '))
        if ($fields.ContainsKey($key)) {
            $duplicateFields = $true
        }
        $fields[$key] = $value
    }

    $expectedIdPattern = ''
    $expectedTestValue = ''
    $expectedName = ''
    $expectedMarker = ''
    if ($Path -eq '/test-concurrent-a') {
        $expectedIdPattern = '^phase3-A-[0-9a-f]{32}$'
        $expectedTestValue = 'alpha-modified'
        $expectedName = 'case-A'
        $expectedMarker = 'keep-A'
    } elseif ($Path -eq '/test-concurrent-b') {
        $expectedIdPattern = '^phase3-B-[0-9a-f]{32}$'
        $expectedTestValue = 'beta-modified'
        $expectedName = 'case-B'
        $expectedMarker = 'keep-B'
    }

    $testId = ''
    if ($fields.ContainsKey('test_id')) { $testId = $fields['test_id'] }
    $testIdVerified = ($expectedIdPattern -ne '' -and $testId -match $expectedIdPattern)
    $mcpTestModified = ($fields.ContainsKey('mcp_test') -and $fields['mcp_test'] -eq $expectedTestValue)
    $nameFieldPreserved = ($fields.ContainsKey('name') -and $fields['name'] -eq $expectedName)
    $markerFieldPreserved = ($fields.ContainsKey('marker') -and $fields['marker'] -eq $expectedMarker)
    $fieldSetVerified = (
        $fields.Count -eq 4 -and
        $pairs.Length -eq 4 -and
        -not $duplicateFields -and
        -not $malformedField -and
        $fields.ContainsKey('test_id') -and
        $fields.ContainsKey('mcp_test') -and
        $fields.ContainsKey('name') -and
        $fields.ContainsKey('marker')
    )
    $requestContentLengthMatchesBody = (
        $RequestContentLength -eq [System.Text.Encoding]::UTF8.GetByteCount($Body) -and
        $BytesRead -eq $RequestContentLength
    )
    $serverVerified = (
        $contentTypeVerified -and
        $fieldSetVerified -and
        $testIdVerified -and
        $mcpTestModified -and
        $nameFieldPreserved -and
        $markerFieldPreserved -and
        $requestContentLengthMatchesBody
    )

    [pscustomobject]@{
        Path = $Path
        TestId = $testId
        TestIdVerified = $testIdVerified
        McpTestModified = $mcpTestModified
        NameFieldPreserved = $nameFieldPreserved
        MarkerFieldPreserved = $markerFieldPreserved
        FieldCount = $pairs.Length
        ContentTypeVerified = $contentTypeVerified
        RequestContentLength = $RequestContentLength
        RequestBodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($Body)
        RequestContentLengthMatchesBody = $requestContentLengthMatchesBody
        ServerVerified = $serverVerified
    }
}

function Get-TestUploadVerification {
    param(
        [string]$ContentTypeHeader,
        [string]$Body,
        [int]$RequestContentLength,
        [int]$BytesRead,
        [string]$ExpectedFileText
    )

    $crlf = [string]([char]13) + [char]10
    $doubleCrlf = $crlf + $crlf
    $contentTypeVerified = $false
    $boundary = ''
    $boundaryMatch = [regex]::Match(
        $ContentTypeHeader,
        '(?i)(?:^|;)\s*boundary=(?:"(?<quoted>[^"]+)"|(?<plain>[^;\s]+))'
    )
    if (-not [string]::IsNullOrWhiteSpace($ContentTypeHeader)) {
        $mediaType = ($ContentTypeHeader -split ';', 2)[0].Trim()
        $contentTypeVerified = $mediaType -ieq 'multipart/form-data' -and $boundaryMatch.Success
    }
    if ($boundaryMatch.Success) {
        if ($boundaryMatch.Groups['quoted'].Success) {
            $boundary = $boundaryMatch.Groups['quoted'].Value
        } else {
            $boundary = $boundaryMatch.Groups['plain'].Value
        }
    }

    $boundaryTokenValid = $boundary -match '^[A-Za-z0-9_-]{1,70}$'
    $boundaryVerified = $false
    $partCount = 0
    $partsByName = @{}
    $duplicatePartNames = $false
    $malformedPart = $false
    if ($boundaryTokenValid) {
        $prefix = "--$boundary$crlf"
        $separator = "$crlf--$boundary$crlf"
        $closing = "$crlf--$boundary--$crlf"
        $markersValid = (
            $Body.StartsWith($prefix, [System.StringComparison]::Ordinal) -and
            $Body.EndsWith($closing, [System.StringComparison]::Ordinal)
        )
        if ($markersValid) {
            $middleLength = $Body.Length - $prefix.Length - $closing.Length
            if ($middleLength -ge 0) {
                $middle = $Body.Substring($prefix.Length, $middleLength)
                $parts = $middle.Split(
                    [string[]]@($separator),
                    [System.StringSplitOptions]::None
                )
                $partCount = $parts.Length
                $boundaryVerified = ($partCount -eq 4)
                foreach ($part in $parts) {
                    $partHeaderEnd = $part.IndexOf($doubleCrlf, [System.StringComparison]::Ordinal)
                    if ($partHeaderEnd -lt 0) {
                        $malformedPart = $true
                        continue
                    }
                    $partHeaderText = $part.Substring(0, $partHeaderEnd)
                    $partBody = $part.Substring($partHeaderEnd + $doubleCrlf.Length)
                    $disposition = [regex]::Match(
                        $partHeaderText,
                        '(?im)^Content-Disposition:\s*form-data;\s*name=(?:"(?<name>[^"]+)"|(?<namePlain>[^;\s]+))(?:;\s*filename=(?:"(?<filename>[^"]*)"|(?<filenamePlain>[^;\s]+)))?(?:;[^\r\n]*)?$'
                    )
                    if (-not $disposition.Success) {
                        $malformedPart = $true
                        continue
                    }
                    $name = if ($disposition.Groups['name'].Success) { $disposition.Groups['name'].Value } else { $disposition.Groups['namePlain'].Value }
                    if ($partsByName.ContainsKey($name)) {
                        $duplicatePartNames = $true
                    }
                    $filenamePresent = $disposition.Groups['filename'].Success -or $disposition.Groups['filenamePlain'].Success
                    $filenameValue = if ($disposition.Groups['filename'].Success) {
                        $disposition.Groups['filename'].Value
                    } else {
                        $disposition.Groups['filenamePlain'].Value
                    }
                    $partContentType = ''
                    $contentTypeMatch = [regex]::Match($partHeaderText, '(?im)^Content-Type:\s*(?<type>[^\r\n]+)')
                    if ($contentTypeMatch.Success) {
                        $partContentType = $contentTypeMatch.Groups['type'].Value.Trim()
                    }
                    $partsByName[$name] = [pscustomobject]@{
                        HasFilename = $filenamePresent
                        Filename = $filenameValue
                        ContentType = $partContentType
                        Body = $partBody
                    }
                }
            }
        }
    }

    $mcpTestModified = $false
    $nameFieldPreserved = $false
    $noteFieldPreserved = $false
    if ($partsByName.ContainsKey('mcp_test')) {
        $field = $partsByName['mcp_test']
        $mcpTestModified = (-not $field.HasFilename -and $field.Body -eq 'modified')
    }
    if ($partsByName.ContainsKey('name')) {
        $field = $partsByName['name']
        $nameFieldPreserved = (-not $field.HasFilename -and $field.Body -eq 'test')
    }
    if ($partsByName.ContainsKey('note')) {
        $field = $partsByName['note']
        $noteFieldPreserved = (-not $field.HasFilename -and $field.Body -eq 'keep-this')
    }

    $expectedFileBytes = [System.Text.Encoding]::ASCII.GetBytes($ExpectedFileText)
    $uploadedFileBytes = [byte[]]@()
    $filenameVerified = $false
    $fileContentTypeVerified = $false
    if ($partsByName.ContainsKey('file')) {
        $filePart = $partsByName['file']
        $filenameVerified = ($filePart.HasFilename -and $filePart.Filename -eq 'burp_mcp_test.txt')
        $fileContentTypeVerified = ($filePart.ContentType -ieq 'text/plain')
        $uploadedFileBytes = [System.Text.Encoding]::ASCII.GetBytes($filePart.Body)
    }
    $fileBytesMatch = ($uploadedFileBytes.Length -eq $expectedFileBytes.Length)
    if ($fileBytesMatch) {
        for ($index = 0; $index -lt $expectedFileBytes.Length; $index++) {
            if ($uploadedFileBytes[$index] -ne $expectedFileBytes[$index]) {
                $fileBytesMatch = $false
                break
            }
        }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $uploadedFileSha256 = ([BitConverter]::ToString($sha.ComputeHash($uploadedFileBytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $bodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($Body)
    $contentLengthMatchesBody = (
        $RequestContentLength -eq $bodyByteLength -and
        $BytesRead -eq $RequestContentLength
    )
    $partSetVerified = (
        $partsByName.Count -eq 4 -and
        -not $duplicatePartNames -and
        -not $malformedPart -and
        $partsByName.ContainsKey('mcp_test') -and
        $partsByName.ContainsKey('name') -and
        $partsByName.ContainsKey('note') -and
        $partsByName.ContainsKey('file')
    )
    $serverVerified = (
        $contentTypeVerified -and
        $boundaryVerified -and
        $partSetVerified -and
        $mcpTestModified -and
        $nameFieldPreserved -and
        $noteFieldPreserved -and
        $filenameVerified -and
        $fileContentTypeVerified -and
        $fileBytesMatch -and
        $contentLengthMatchesBody
    )

    [pscustomobject]@{
        ContentTypeVerified = $contentTypeVerified
        BoundaryVerified = $boundaryVerified
        PartCount = $partCount
        McpTestModified = $mcpTestModified
        NameFieldPreserved = $nameFieldPreserved
        NoteFieldPreserved = $noteFieldPreserved
        FilenameVerified = $filenameVerified
        FileContentTypeVerified = $fileContentTypeVerified
        FileByteLength = $uploadedFileBytes.Length
        FileSha256 = $uploadedFileSha256
        FileBytesMatch = $fileBytesMatch
        RequestContentLength = $RequestContentLength
        RequestBodyByteLength = $bodyByteLength
        RequestContentLengthMatchesBody = $contentLengthMatchesBody
        ServerVerified = $serverVerified
    }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8000)
$listener.Start()
Write-Host "Local test server listening on http://127.0.0.1:8000/ (maximum $MaxRequests requests, $MaxRunSeconds seconds). Log: $LogPath"

try {
    $requestCount = 0
    $serverClock = [System.Diagnostics.Stopwatch]::StartNew()
    while ($requestCount -lt $MaxRequests -and $serverClock.Elapsed.TotalSeconds -lt $MaxRunSeconds) {
        if (-not $listener.Pending()) {
            Start-Sleep -Milliseconds 50
            continue
        }
        $client = $listener.AcceptTcpClient()
        $requestCount++
        try {
            $stream = $client.GetStream()
            $stream.ReadTimeout = $RequestTimeoutSeconds * 1000
            $stream.WriteTimeout = $RequestTimeoutSeconds * 1000
            $requestLine = Read-TestHttpLine -Stream $stream
            if ([string]::IsNullOrWhiteSpace($requestLine)) { continue }

            $requestParts = $requestLine.Split(' ', 3)
            if ($requestParts.Length -ne 3 -or $requestParts[2] -notmatch '^HTTP/1\.[01]$') {
                Send-TestHttpResponse -Stream $stream -Status '400 Bad Request' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Malformed request line'))
                continue
            }
            $method = $requestParts[0]
            $requestTarget = $requestParts[1]
            $requestHeaders = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if ($requestTarget -match '^https?://') {
                $targetUri = $null
                if (-not [Uri]::TryCreate($requestTarget, [UriKind]::Absolute, [ref]$targetUri)) {
                    Send-TestHttpResponse -Stream $stream -Status '400 Bad Request' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Malformed request target'))
                    continue
                }
                $path = $targetUri.AbsolutePath
                $query = $targetUri.Query.TrimStart('?')
            } else {
                $targetParts = $requestTarget.Split('?', 2)
                $path = $targetParts[0]
                $query = if ($targetParts.Length -gt 1) { $targetParts[1] } else { '' }
            }
            $knownTestPaths = @(
                '/live-check', '/test-html', '/test-post', '/test-post-phase2', '/test-form', '/test-upload',
                '/test-cookie', '/test-set-cookie', '/test-cancel', '/test-timeout',
                '/test-session-expiry', '/test-concurrent-a', '/test-concurrent-b',
                '/test-binary', '/test-unicode', '/test-empty', '/test-large', '/test-method', '/test-headers'
            )
            $loggedPath = if ($path -in $knownTestPaths) { $path } else { '/<unrecognized>' }
            $headerBytesRead = [System.Text.Encoding]::ASCII.GetByteCount($requestLine) + 2
            $malformedHeaders = $false
            $duplicateFramingHeader = $false
            while ($true) {
                $line = Read-TestHttpLine -Stream $stream
                if ([string]::IsNullOrEmpty($line)) { break }
                $headerBytesRead += [System.Text.Encoding]::ASCII.GetByteCount($line) + 2
                if ($headerBytesRead -gt 16384) { $malformedHeaders = $true; break }
                $colon = $line.IndexOf(':')
                if ($colon -le 0) { $malformedHeaders = $true; break }
                $name = $line.Substring(0, $colon).Trim()
                $value = $line.Substring($colon + 1).Trim()
                if ($name -notmatch '^[!#$%&''*+.^_`|~0-9A-Za-z-]{1,128}$') { $malformedHeaders = $true; break }
                if ($requestHeaders.ContainsKey($name)) {
                    if ($name -in @('Content-Length', 'Transfer-Encoding')) { $duplicateFramingHeader = $true }
                    else { $requestHeaders[$name] = "$($requestHeaders[$name]), $value" }
                } else {
                    $requestHeaders[$name] = $value
                }
            }
            if ($headerBytesRead -gt 16384 -or $malformedHeaders -or $duplicateFramingHeader) {
                Send-TestHttpResponse -Stream $stream -Status '400 Bad Request' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Malformed or oversized HTTP headers'))
                continue
            }

            $contentLength = 0
            $hasContentLength = $requestHeaders.ContainsKey('Content-Length')
            $hasTransferEncoding = $requestHeaders.ContainsKey('Transfer-Encoding')
            if ($hasContentLength -and $hasTransferEncoding) {
                Send-TestHttpResponse -Stream $stream -Status '400 Bad Request' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Conflicting HTTP body framing'))
                continue
            }
            if ($hasTransferEncoding) {
                Send-TestHttpResponse -Stream $stream -Status '501 Not Implemented' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Chunked request bodies are not supported by this test server'))
                continue
            }
            if ($hasContentLength) {
                $parsedLength = 0
                if (-not [int]::TryParse($requestHeaders['Content-Length'], [ref]$parsedLength) -or $parsedLength -lt 0) {
                    Send-TestHttpResponse -Stream $stream -Status '400 Bad Request' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Invalid Content-Length'))
                    continue
                }
                if ($parsedLength -gt $MaxBodyBytes) {
                    Send-TestHttpResponse -Stream $stream -Status '413 Content Too Large' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Request body exceeds the configured test limit'))
                    continue
                }
                $contentLength = $parsedLength
            }

            $bodyBytes = New-Object byte[] $contentLength
            $totalRead = 0
            if ($contentLength -gt 0) {
                while ($totalRead -lt $contentLength) {
                    $read = $stream.Read($bodyBytes, $totalRead, $contentLength - $totalRead)
                    if ($read -le 0) { break }
                    $totalRead += $read
                }
                if ($totalRead -ne $contentLength) {
                    Send-TestHttpResponse -Stream $stream -Status '400 Bad Request' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Request body ended before Content-Length'))
                    continue
                }
            }
            $utf8BodyValid = $true
            try { $requestBody = [System.Text.UTF8Encoding]::new($false, $true).GetString($bodyBytes) }
            catch { $requestBody = ''; $utf8BodyValid = $false }

            if ($method -eq 'GET' -and $path -eq '/__phase4a-health' -and $contentLength -eq 0 -and $totalRead -eq 0) {
                if ($TestRunId) {
                    $healthIdentityMatches = $requestHeaders.ContainsKey('X-MCP-Test-Run') -and
                        $requestHeaders['X-MCP-Test-Run'] -ceq $TestRunId -and
                        $requestHeaders.ContainsKey('X-MCP-Server-Identity') -and
                        $requestHeaders['X-MCP-Server-Identity'] -ceq $ServerIdentity -and
                        $requestHeaders.ContainsKey('Host') -and
                        $requestHeaders['Host'] -ceq '127.0.0.1:8000'
                    if (-not $healthIdentityMatches) {
                        Send-TestHttpResponse -Stream $stream -Status '403 Forbidden' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Synthetic health identity rejected'))
                        continue
                    }
                }
                $healthBody = [System.Text.Encoding]::ASCII.GetBytes('MCP_LOCAL_TEST_SERVER_READY')
                $healthHeaders = @()
                if ($TestRunId) {
                    $healthHeaders = @(
                        "X-MCP-Test-Run: $TestRunId",
                        "X-MCP-Server-Identity: $ServerIdentity"
                    )
                }
                Send-TestHttpResponse -Stream $stream -Status '200 OK' -ContentType 'text/plain; charset=us-ascii' -ExtraHeaders $healthHeaders -BodyBytes $healthBody
                continue
            }

            if ($TestRunId) {
                $allowedUnattendedPaths = @(
                    '/test-html', '/test-post', '/test-form', '/test-upload', '/test-cancel',
                    '/test-timeout', '/test-session-expiry', '/test-concurrent-a', '/test-concurrent-b'
                )
                $identityMatches = $requestHeaders.ContainsKey('X-MCP-Test-Run') -and
                    $requestHeaders['X-MCP-Test-Run'] -ceq $TestRunId -and
                    $requestHeaders.ContainsKey('X-MCP-Server-Identity') -and
                    $requestHeaders['X-MCP-Server-Identity'] -ceq $ServerIdentity -and
                    $requestHeaders.ContainsKey('Host') -and
                    $requestHeaders['Host'] -ceq '127.0.0.1:8000'
                if ($path -notin $allowedUnattendedPaths -or -not $identityMatches) {
                    Send-TestHttpResponse -Stream $stream -Status '403 Forbidden' -BodyBytes ([System.Text.Encoding]::ASCII.GetBytes('Synthetic test identity or path rejected'))
                    continue
                }
            }

            $postBodyVerified = $null
            $postEnabled = $null
            $postJson = $null
            if ($path -eq '/test-post' -or $path -ceq '/test-post-phase2') {
                $postBodyVerified = $false
                try {
                    $postJson = ConvertFrom-Json -InputObject $requestBody -ErrorAction Stop
                    $postBodyVerified = ($postJson.name -eq 'original' -and $postJson.mcp_test -eq 'after')
                    if ($postJson.PSObject.Properties.Name -contains 'enabled') { $postEnabled = $postJson.enabled }
                } catch { }
            }
            $testCookieVerified = $null
            if ($path -eq '/test-cookie') {
                $testCookieVerified = $false
                if ($requestHeaders.ContainsKey('Cookie')) {
                    foreach ($cookiePair in ($requestHeaders['Cookie'] -split ';')) {
                        $parts = $cookiePair.Trim().Split('=', 2)
                        if ($parts.Length -eq 2 -and $parts[0].Trim() -eq 'mcp_test') {
                            $testCookieVerified = ($parts[1] -eq 'modified')
                            break
                        }
                    }
                }
            }
            $formNameFieldUnchanged = $null
            $formMcpTestModified = $null
            $formFieldCount = $null
            $formContentTypeVerified = $null
            $requestContentLengthMatchesBody = $null
            $formBodyVerified = $null
            if ($path -eq '/test-form') {
                $formContentTypeVerified = $false
                if ($requestHeaders.ContainsKey('Content-Type')) {
                    $formMediaType = ($requestHeaders['Content-Type'] -split ';', 2)[0].Trim()
                    $formContentTypeVerified = $formMediaType -ieq 'application/x-www-form-urlencoded'
                }
                $formPairs = $requestBody.Split('&')
                $formFields = @{}
                $formDuplicateFields = $false
                foreach ($pair in $formPairs) {
                    $parts = $pair.Split('=', 2)
                    if ($parts.Length -ne 2) {
                        $formDuplicateFields = $true
                        continue
                    }
                    $key = [Uri]::UnescapeDataString($parts[0].Replace('+', ' '))
                    $value = [Uri]::UnescapeDataString($parts[1].Replace('+', ' '))
                    if ($formFields.ContainsKey($key)) {
                        $formDuplicateFields = $true
                    }
                    $formFields[$key] = $value
                }
                $formNameFieldUnchanged = ($formFields.ContainsKey('name') -and $formFields['name'] -eq 'test')
                $formMcpTestModified = ($formFields.ContainsKey('mcp_test') -and $formFields['mcp_test'] -eq 'modified')
                $formFieldCount = $formPairs.Length
                $requestContentLengthMatchesBody = (
                    $contentLength -eq [System.Text.Encoding]::UTF8.GetByteCount($requestBody) -and
                    $totalRead -eq $contentLength
                )
                $formBodyVerified = (
                    $formFieldCount -eq 2 -and
                    $formFields.Count -eq 2 -and
                    -not $formDuplicateFields -and
                    $formNameFieldUnchanged -and
                    $formMcpTestModified -and
                    $formContentTypeVerified -and
                    $requestContentLengthMatchesBody
                )
            }
            $multipartVerification = $null
            if ($path -eq '/test-upload') {
                $contentTypeHeader = ''
                if ($requestHeaders.ContainsKey('Content-Type')) {
                    $contentTypeHeader = $requestHeaders['Content-Type']
                }
                $uploadArguments = @{
                    ContentTypeHeader = $contentTypeHeader
                    Body = $requestBody
                    RequestContentLength = $contentLength
                    BytesRead = $totalRead
                    ExpectedFileText = 'Burp MCP multipart upload test data only.'
                }
                $multipartVerification = Get-TestUploadVerification @uploadArguments
                $requestContentLengthMatchesBody = $multipartVerification.RequestContentLengthMatchesBody
            }
            $concurrentVerification = $null
            if ($path -eq '/test-concurrent-a' -or $path -eq '/test-concurrent-b') {
                $contentTypeHeader = ''
                if ($requestHeaders.ContainsKey('Content-Type')) {
                    $contentTypeHeader = $requestHeaders['Content-Type']
                }
                $concurrentArguments = @{
                    Path = $path
                    ContentTypeHeader = $contentTypeHeader
                    Body = $requestBody
                    RequestContentLength = $contentLength
                    BytesRead = $totalRead
                }
                $concurrentVerification = Get-ConcurrentFormVerification @concurrentArguments
                $requestContentLengthMatchesBody = $concurrentVerification.RequestContentLengthMatchesBody
            }
            $cancellationTestId = $null
            $cancellationTestIdVerified = $null
            $cancellationRequestVerified = $null
            if ($path -eq '/test-cancel') {
                $cancellationTestIdVerified = $false
                if ($requestHeaders.ContainsKey('X-MCP-Test-ID')) {
                    $candidateTestId = $requestHeaders['X-MCP-Test-ID']
                    $cancellationTestIdVerified = ($candidateTestId -match '^phase4a-[0-9a-f]{32}$')
                    if ($cancellationTestIdVerified) { $cancellationTestId = $candidateTestId }
                }
                $cancellationRequestVerified = (
                    $method -eq 'GET' -and
                    $cancellationTestIdVerified -and
                    $contentLength -eq 0 -and
                    $totalRead -eq 0
                )
            }
            $record = [ordered]@{
                receivedAt = [DateTimeOffset]::Now.ToString('o')
                method = $method
                path = $loggedPath
                contentLength = $contentLength
                bodyByteLength = $bodyBytes.Length
                bodySha256 = Get-TestSha256 -Bytes $bodyBytes
                utf8BodyValid = $utf8BodyValid
                bodyFramingVerified = ($contentLength -eq $bodyBytes.Length -and $totalRead -eq $contentLength)
                postBodyVerified = $postBodyVerified
                testCookieVerified = $testCookieVerified
                formNameFieldUnchanged = $formNameFieldUnchanged
                formMcpTestModified = $formMcpTestModified
                formFieldCount = $formFieldCount
                formContentTypeVerified = $formContentTypeVerified
                requestContentLengthMatchesBody = $requestContentLengthMatchesBody
                formBodyVerified = $formBodyVerified
                multipartContentTypeVerified = $multipartVerification.ContentTypeVerified
                multipartBoundaryVerified = $multipartVerification.BoundaryVerified
                multipartPartCount = $multipartVerification.PartCount
                multipartMcpTestModified = $multipartVerification.McpTestModified
                multipartNameFieldPreserved = $multipartVerification.NameFieldPreserved
                multipartNoteFieldPreserved = $multipartVerification.NoteFieldPreserved
                multipartFilenameVerified = $multipartVerification.FilenameVerified
                multipartFileContentTypeVerified = $multipartVerification.FileContentTypeVerified
                multipartFileByteLength = $multipartVerification.FileByteLength
                multipartFileSha256 = $multipartVerification.FileSha256
                multipartFileBytesMatch = $multipartVerification.FileBytesMatch
                multipartBodyVerified = $multipartVerification.ServerVerified
                concurrentTestId = $concurrentVerification.TestId
                concurrentTestIdVerified = $concurrentVerification.TestIdVerified
                concurrentMcpTestModified = $concurrentVerification.McpTestModified
                concurrentNameFieldPreserved = $concurrentVerification.NameFieldPreserved
                concurrentMarkerFieldPreserved = $concurrentVerification.MarkerFieldPreserved
                concurrentFieldCount = $concurrentVerification.FieldCount
                concurrentContentTypeVerified = $concurrentVerification.ContentTypeVerified
                concurrentContentLengthMatchesBody = $concurrentVerification.RequestContentLengthMatchesBody
                concurrentBodyVerified = $concurrentVerification.ServerVerified
                cancellationTestId = $cancellationTestId
                cancellationTestIdVerified = $cancellationTestIdVerified
                cancellationRequestVerified = $cancellationRequestVerified
            }
            if ($RuleEngineTestMode) {
                $ruleTestId = $null
                if ($requestHeaders.ContainsKey('X-MCP-Test-ID') -and $requestHeaders['X-MCP-Test-ID'] -match '^[A-Za-z0-9_-]{1,64}$') {
                    $ruleTestId = $requestHeaders['X-MCP-Test-ID']
                }
                $record['ruleTestId'] = $ruleTestId
                $record['postEnabled'] = $postEnabled
                $record['expectedLocalHostObserved'] = $requestHeaders.ContainsKey('Host') -and $requestHeaders['Host'] -ceq '127.0.0.1:8000'
                $record['localhostAliasHostObserved'] = $requestHeaders.ContainsKey('Host') -and $requestHeaders['Host'] -ceq 'localhost:8000'
                $record['ruleTestHeaderObserved'] = $requestHeaders.ContainsKey('X-MCP-Rule-Test') -and $requestHeaders['X-MCP-Rule-Test'] -ceq 'active'
                $record['pauseHeaderObserved'] = $requestHeaders.ContainsKey('X-MCP-Pause-Forward') -and $requestHeaders['X-MCP-Pause-Forward'] -ceq 'active'
            }
            $recordJson = ConvertTo-Json -InputObject $record -Compress -Depth 4
            [System.IO.File]::AppendAllText($LogPath, $recordJson + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

            $status = '200 OK'
            $contentType = 'text/plain; charset=utf-8'
            $extraHeaders = @()
            switch ($path) {
                '/live-check' {
                    $responseBody = 'Burp MCP local test endpoint'
                }
                '/test-form' {
                    $contentType = 'application/json; charset=utf-8'
                    $formResult = [ordered]@{
                        method = $method
                        path = $path
                        requestContentLength = $contentLength
                        requestBodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($requestBody)
                        nameFieldUnchanged = $formNameFieldUnchanged
                        mcpTestModified = $formMcpTestModified
                        formFieldCount = $formFieldCount
                        formContentTypeVerified = $formContentTypeVerified
                        requestContentLengthMatchesBody = $requestContentLengthMatchesBody
                        serverVerified = $formBodyVerified
                    }
                    $responseBody = ConvertTo-Json -InputObject $formResult -Compress -Depth 4
                }
                '/test-upload' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject $multipartVerification -Compress -Depth 4
                }
                '/test-concurrent-a' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject $concurrentVerification -Compress -Depth 4
                }
                '/test-concurrent-b' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject $concurrentVerification -Compress -Depth 4
                }
                '/test-cancel' {
                    $contentType = 'application/json; charset=utf-8'
                    $cancelResult = [ordered]@{
                        method = $method
                        path = $path
                        testId = $cancellationTestId
                        testIdVerified = $cancellationTestIdVerified
                        requestContentLength = $contentLength
                        requestBodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($requestBody)
                        serverVerified = $cancellationRequestVerified
                    }
                    $responseBody = ConvertTo-Json -InputObject $cancelResult -Compress -Depth 4
                }
                '/test-timeout' {
                    $delayMilliseconds = $TimeoutDelayMilliseconds
                    if ($query -match '(?:^|&)delayMs=(?<delay>[0-9]{1,5})(?:&|$)') {
                        $delayMilliseconds = [Math]::Min(10000, [int]$Matches['delay'])
                    }
                    if ($delayMilliseconds -gt 0) { Start-Sleep -Milliseconds $delayMilliseconds }
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject ([ordered]@{
                        path = '/test-timeout'
                        delayMilliseconds = $delayMilliseconds
                        requestContentLength = $contentLength
                        requestBodyByteLength = $bodyBytes.Length
                    }) -Compress -Depth 3
                }
                '/test-session-expiry' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = '{"path":"/test-session-expiry","serverVerified":true}'
                }
                '/test-binary' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject ([ordered]@{
                        path = '/test-binary'
                        bodyByteLength = $bodyBytes.Length
                        bodySha256 = (Get-TestSha256 -Bytes $bodyBytes)
                        contentLengthMatchesBody = ($contentLength -eq $bodyBytes.Length -and $totalRead -eq $contentLength)
                    }) -Compress -Depth 3
                }
                '/test-unicode' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject ([ordered]@{
                        path = '/test-unicode'
                        utf8Valid = $utf8BodyValid
                        bodyByteLength = $bodyBytes.Length
                        bodySha256 = (Get-TestSha256 -Bytes $bodyBytes)
                        contentLengthMatchesBody = ($contentLength -eq $bodyBytes.Length -and $totalRead -eq $contentLength)
                    }) -Compress -Depth 3
                }
                '/test-empty' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject ([ordered]@{
                        path = '/test-empty'
                        emptyBody = ($bodyBytes.Length -eq 0)
                        contentLengthMatchesBody = ($contentLength -eq $bodyBytes.Length -and $totalRead -eq $contentLength)
                    }) -Compress -Depth 3
                }
                '/test-large' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject ([ordered]@{
                        path = '/test-large'
                        bodyByteLength = $bodyBytes.Length
                        bodySha256 = (Get-TestSha256 -Bytes $bodyBytes)
                        maxBodyBytes = $MaxBodyBytes
                        contentLengthMatchesBody = ($contentLength -eq $bodyBytes.Length -and $totalRead -eq $contentLength)
                    }) -Compress -Depth 3
                }
                { $_ -eq '/test-method' -or $_ -ceq '/test-post-phase2' } {
                    $contentType = 'application/json; charset=utf-8'
                    try {
                        $responseBody = ConvertTo-Json -InputObject (New-TestMethodFixtureResponse `
                            -Path $path -Method $method -BodyBytes $bodyBytes `
                            -BodySha256 (Get-TestSha256 -Bytes $bodyBytes) -RuleEngineTestMode ([bool]$RuleEngineTestMode) `
                            -ContentType $requestHeaders['Content-Type'] -TestId $requestHeaders['X-MCP-Test-ID']) -Compress -Depth 8
                    } catch {
                        $status = '400 Bad Request'
                        $responseBody = 'Invalid synthetic method-fixture request.'
                    }
                }
                '/test-headers' {
                    $extraHeaders += 'X-MCP-Test-Origin: loopback'
                    $responseBody = 'Synthetic local response header fixture'
                }
                '/test-post' {
                    $contentType = 'application/json; charset=utf-8'
                    if ($RuleEngineTestMode) {
                        if ($null -eq $postJson -or $postJson -isnot [pscustomobject]) {
                            $status = '400 Bad Request'
                            $responseBody = 'Rule-engine test mode requires a JSON object.'
                            break
                        }
                        $postResponse = [ordered]@{}
                        foreach ($property in $postJson.PSObject.Properties) {
                            $postResponse[$property.Name] = $property.Value
                        }
                        $postResponse['enabled'] = $false
                        $responseBody = ConvertTo-Json -InputObject $postResponse -Compress -Depth 16
                        if ($requestHeaders.ContainsKey('X-MCP-Pause-Forward') -and $requestHeaders['X-MCP-Pause-Forward'] -ceq 'active') {
                            $extraHeaders += 'X-MCP-Pause-Forward: active'
                        }
                    } else {
                        $responseBody = $requestBody
                    }
                }
                '/test-cookie' {
                    $responseBody = 'Dedicated test cookie recorded by local server'
                }
                '/test-set-cookie' {
                    $extraHeaders += 'Set-Cookie: mcp_test=original; Path=/; SameSite=Lax'
                    $responseBody = 'Dedicated Set-Cookie test response'
                }
                '/test-html' {
                    $contentType = 'text/html; charset=utf-8'
                    $responseBody = '<!doctype html><html><head><title>Burp MCP HTML Test</title></head><body><p>Preserve this paragraph.</p><h1>Original Page</h1></body></html>'
                }
                default {
                    $status = '404 Not Found'
                    $responseBody = 'Not found'
                }
            }

            $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
            Send-TestHttpResponse -Stream $stream -Status $status -ContentType $contentType -ExtraHeaders $extraHeaders -BodyBytes $responseBytes
        } catch {
            Write-Warning "Local test request failed ($($_.Exception.GetType().Name), line $($_.InvocationInfo.ScriptLineNumber)); connection closed. Request content was not logged."
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
