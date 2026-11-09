$ErrorActionPreference = 'Stop'

$javaVersionLine = (& java -version 2>&1 | Select-Object -First 1)
if ($javaVersionLine -notmatch 'version "(?:1\.)?(\d+)') {
    throw "Could not determine the installed Java version. Install Java 17 or later and confirm java.exe is on PATH."
}
$javaMajor = [int]$Matches[1]
if ($javaMajor -lt 17) {
    throw "Java 17 or later is required. Found Java $javaMajor."
}

$gradle = Join-Path $PSScriptRoot 'gradlew.bat'
& $gradle clean test shadowJar
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$jar = Join-Path $PSScriptRoot 'build\libs\burp-mcp-all.jar'
if (-not (Test-Path -LiteralPath $jar)) {
    throw "Gradle completed but the extension JAR was not found at $jar"
}
Write-Host "Built Burp MCP extension: $jar"
