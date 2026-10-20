$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    dotnet build -c Release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet run --project samples/AccessControlStudio.DemoClient -c Release --no-build -- src/AccessControlStudio.Api/bin/Release/net10.0/AccessControlStudio.Api.dll
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
