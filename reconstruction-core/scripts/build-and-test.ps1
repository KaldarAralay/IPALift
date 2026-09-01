[CmdletBinding()]
param(
    [Parameter()] [string] $ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter()] [string] $ConfigurePreset = 'windows-x64',
    [Parameter()] [string] $BuildPreset = 'windows-x64-release',
    [Parameter()] [string] $TestPreset = 'windows-x64-release',
    [Parameter()] [string] $GeneratorInstance = ''
)

$ErrorActionPreference = 'Stop'
$resolvedProject = (Resolve-Path -LiteralPath $ProjectRoot).Path
$presetPath = Join-Path $resolvedProject 'CMakePresets.json'
if (-not (Test-Path -LiteralPath $presetPath)) {
    throw "Project does not contain CMakePresets.json: $resolvedProject"
}

function Test-VisualStudioInstallation {
    param([Parameter(Mandatory)] [string] $Path)

    return (Test-Path -LiteralPath (Join-Path $Path 'VC\Auxiliary\Build\vcvarsall.bat'))
}

function Resolve-VisualStudioInstance {
    param([Parameter()] [string] $RequestedInstance = '')

    if (-not [string]::IsNullOrWhiteSpace($RequestedInstance)) {
        $resolved = [IO.Path]::GetFullPath($RequestedInstance)
        if (-not (Test-VisualStudioInstallation -Path $resolved)) {
            throw "Visual Studio instance does not contain the C++ workload: $resolved"
        }
        return $resolved
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:VSINSTALLDIR)) {
        $candidates.Add($env:VSINSTALLDIR)
    }

    $vswherePaths = [System.Collections.Generic.List[string]]::new()
    $vswhereCommand = Get-Command 'vswhere.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $vswhereCommand) {
        $vswherePaths.Add($vswhereCommand.Source)
    }
    foreach ($programFilesRoot in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not [string]::IsNullOrWhiteSpace($programFilesRoot)) {
            $vswherePaths.Add((Join-Path $programFilesRoot 'Microsoft Visual Studio\Installer\vswhere.exe'))
        }
    }
    foreach ($vswherePath in $vswherePaths | Select-Object -Unique) {
        if (Test-Path -LiteralPath $vswherePath) {
            $discovered = & $vswherePath -latest -products '*' `
                -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' `
                -property installationPath
            if ($LASTEXITCODE -eq 0) {
                foreach ($instance in @($discovered)) {
                    if (-not [string]::IsNullOrWhiteSpace($instance)) {
                        $candidates.Add($instance.Trim())
                    }
                }
            }
        }
    }

    foreach ($programFilesRoot in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ([string]::IsNullOrWhiteSpace($programFilesRoot)) { continue }
        foreach ($edition in @('Enterprise', 'Professional', 'Community', 'BuildTools')) {
            $candidates.Add((Join-Path $programFilesRoot "Microsoft Visual Studio\2022\$edition"))
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-VisualStudioInstallation -Path $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

$presetDocument = Get-Content -LiteralPath $presetPath -Raw | ConvertFrom-Json
$configureDefinition = $presetDocument.configurePresets |
    Where-Object { $_.name -eq $ConfigurePreset } |
    Select-Object -First 1
$usesVisualStudioGenerator =
    $null -ne $configureDefinition -and
    ([string] $configureDefinition.generator).StartsWith('Visual Studio ', [StringComparison]::Ordinal)
$configureArguments = @('--preset', $ConfigurePreset)
if ($usesVisualStudioGenerator) {
    $visualStudioInstance = Resolve-VisualStudioInstance -RequestedInstance $GeneratorInstance
    if ($null -eq $visualStudioInstance) {
        throw 'Visual Studio 2022 with the Desktop development with C++ workload was not found.'
    }
    Write-Host "Using Visual Studio instance: $visualStudioInstance"
    $configureArguments += "-DCMAKE_GENERATOR_INSTANCE=$visualStudioInstance"
}

Push-Location $resolvedProject
try {
    cmake @configureArguments
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with code $LASTEXITCODE" }
    cmake --build --preset $BuildPreset
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed with code $LASTEXITCODE" }
    ctest --preset $TestPreset
    if ($LASTEXITCODE -ne 0) { throw "CTest failed with code $LASTEXITCODE" }
}
finally {
    Pop-Location
}
