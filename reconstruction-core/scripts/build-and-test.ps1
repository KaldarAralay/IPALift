[CmdletBinding()]
param(
    [Parameter()] [string] $ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter()] [string] $ConfigurePreset = 'windows-x64',
    [Parameter()] [string] $BuildPreset = 'windows-x64-release',
    [Parameter()] [string] $TestPreset = 'windows-x64-release'
)

$ErrorActionPreference = 'Stop'
$resolvedProject = (Resolve-Path -LiteralPath $ProjectRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $resolvedProject 'CMakePresets.json'))) {
    throw "Project does not contain CMakePresets.json: $resolvedProject"
}

Push-Location $resolvedProject
try {
    cmake --preset $ConfigurePreset
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with code $LASTEXITCODE" }
    cmake --build --preset $BuildPreset
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed with code $LASTEXITCODE" }
    ctest --preset $TestPreset
    if ($LASTEXITCODE -ne 0) { throw "CTest failed with code $LASTEXITCODE" }
}
finally {
    Pop-Location
}
