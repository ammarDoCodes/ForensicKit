param(
    [string]$PythonPath = "",
    [string]$EnvironmentPath = ".forensickit-evtx-env"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$environment = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $EnvironmentPath))

if (Test-Path $environment) {
    throw "The EVTX environment already exists at $environment. Remove that exact environment intentionally or choose -EnvironmentPath before retrying."
}

if ($PythonPath) {
    & $PythonPath -m venv --without-pip $environment
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -m venv --without-pip $environment
} else {
    throw "The py -3 launcher was not found. Supply -PythonPath with the bundled Python executable."
}

$venvPython = Join-Path $environment "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "The isolated Python environment did not produce $venvPython."
}

Push-Location $repoRoot
try {
    $packageTarget = Join-Path $environment "Lib\site-packages"
    if ($PythonPath) {
        & $PythonPath -m pip install --no-build-isolation --target $packageTarget --requirement requirements-evtx.txt
    } else {
        & py -3 -m pip install --no-build-isolation --target $packageTarget --requirement requirements-evtx.txt
    }
    if ($LASTEXITCODE -ne 0) {
        throw "The pinned EVTX dependency installation failed with exit code $LASTEXITCODE."
    }
    & $venvPython -c "import Evtx; print('python-evtx=' + getattr(Evtx, '__version__', '0.8.1'))"
    if ($LASTEXITCODE -ne 0) {
        throw "The isolated environment could not import the pinned python-evtx package."
    }
    Write-Output "EVTX environment ready: $venvPython"
    Write-Output "Run: & `"$venvPython`" tests/run_evtx_integration.py --fixture `"C:\path\to\shareable.evtx`""
} finally {
    Pop-Location
}
