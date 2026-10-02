[CmdletBinding()]
param(
    [string]$CaseDirectory,
    [ValidateRange(0, 65535)]
    [int]$Port = 8765,
    [string]$PythonPath
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($CaseDirectory)) {
    $CaseDirectory = Join-Path $projectRoot 'examples\sample-case'
}

try {
    $casePath = (Resolve-Path -LiteralPath $CaseDirectory -ErrorAction Stop).Path
} catch {
    throw "Case directory was not found: $CaseDirectory"
}

if (-not (Test-Path -LiteralPath $casePath -PathType Container)) {
    throw 'The selected case path must be an existing directory.'
}

$runtime = $null
if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
    try {
        $runtime = (Resolve-Path -LiteralPath $PythonPath -ErrorAction Stop).Path
    } catch {
        throw "Python executable was not found: $PythonPath"
    }
    if (Test-Path -LiteralPath $runtime -PathType Container) {
        throw 'PythonPath must point to a Python executable, not a directory.'
    }
} elseif (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'The Windows Python launcher (py -3) was not found. Re-run with -PythonPath "C:\path\to\python.exe".'
}

Push-Location -LiteralPath $projectRoot
try {
    if ($runtime) {
        & $runtime -m forensickit serve $casePath --port $Port
    } else {
        & py -3 -m forensickit serve $casePath --port $Port
    }
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($null -ne $exitCode -and $exitCode -ne 0) {
    throw "ForensicKit workbench exited with code $exitCode."
}
