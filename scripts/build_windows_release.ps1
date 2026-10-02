param(
    [Parameter(Mandatory = $true)]
    [string]$PythonRuntime,
    [string]$ReleaseDirectory
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = '1.2.3'
$evtxStatus = 'EVTX PARTIALLY VALIDATED — pending approved Windows Security and PowerShell binary fixtures'
if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) {
    $ReleaseDirectory = Join-Path (Split-Path $projectRoot -Parent) "forensickit-windows-v$version"
}
$releaseRoot = [IO.Path]::GetFullPath($ReleaseDirectory)
$archivePath = "$releaseRoot.zip"
$archiveDigestPath = "$archivePath.sha256"
$manifestPath = Join-Path $releaseRoot 'release-manifest.json'
$manifestDigestPath = Join-Path $releaseRoot 'release-manifest.sha256'

foreach ($target in @($releaseRoot, $archivePath, $archiveDigestPath)) {
    if (Test-Path -LiteralPath $target) {
        throw "Refusing to overwrite an existing release target: $target"
    }
}
$pythonPath = (Resolve-Path -LiteralPath $PythonRuntime).Path
if ((Split-Path $pythonPath -Leaf) -notin @('python.exe', 'python3.exe')) {
    throw 'PythonRuntime must identify a python.exe executable.'
}
$pythonRoot = Split-Path $pythonPath -Parent
$pythonVersionText = (& $pythonPath --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pythonVersionText -notmatch '^Python 3\.12\.') {
    throw "A working Python 3.12 runtime is required to build the bundled python312 runtime; got: $pythonVersionText"
}
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    throw 'The Windows .NET Framework C# compiler was not found.'
}

function Copy-FilteredTree {
    param([string]$Source, [string]$Destination, [switch]$RuntimeLibrary)
    $sourceRoot = (Resolve-Path -LiteralPath $Source).Path
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($sourceRoot)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        $relativeDirectory = $current.Substring($sourceRoot.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
        $targetDirectory = if ($relativeDirectory) { Join-Path $Destination $relativeDirectory } else { $Destination }
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
        foreach ($directory in Get-ChildItem -LiteralPath $current -Directory -Force) {
            if ($directory.Name -in @('__pycache__', '.git', '.pytest_cache', 'site-packages', 'node_modules', 'reports')) { continue }
            if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $pending.Push($directory.FullName)
        }
        foreach ($file in Get-ChildItem -LiteralPath $current -File -Force) {
            if ($file.Extension -in @('.pyc', '.pyo', '.pyd.tmp')) { continue }
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($RuntimeLibrary -and $file.Name -match '^(pip|setuptools|wheel)(-|\.)') { continue }
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $targetDirectory $file.Name)
        }
    }
}

New-Item -ItemType Directory -Path $releaseRoot | Out-Null
$runtimeRoot = Join-Path $releaseRoot 'runtime'
$appRoot = Join-Path $releaseRoot 'app'
New-Item -ItemType Directory -Path $runtimeRoot, $appRoot | Out-Null

foreach ($name in @('python.exe', 'python3.dll', 'python312.dll', 'vcruntime140.dll', 'vcruntime140_1.dll', 'LICENSE.txt')) {
    $source = Join-Path $pythonRoot $name
    if (-not (Test-Path -LiteralPath $source)) { throw "Required Python runtime component is missing: $name" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $runtimeRoot $name)
}
Copy-FilteredTree -Source (Join-Path $pythonRoot 'DLLs') -Destination (Join-Path $runtimeRoot 'DLLs') -RuntimeLibrary
Copy-FilteredTree -Source (Join-Path $pythonRoot 'Lib') -Destination (Join-Path $runtimeRoot 'Lib') -RuntimeLibrary

foreach ($name in @('forensickit', 'examples', 'schemas')) {
    Copy-FilteredTree -Source (Join-Path $projectRoot $name) -Destination (Join-Path $appRoot $name)
}
New-Item -ItemType Directory -Path (Join-Path $appRoot 'scripts') | Out-Null
foreach ($name in @('forensickit_launcher.cs')) {
    $source = Join-Path $projectRoot "scripts\$name"
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $appRoot 'scripts') }
}
foreach ($name in @('README.md', 'CHANGELOG.md', 'pyproject.toml', 'requirements-evtx.txt', 'THIRD-PARTY-NOTICES.md')) {
    $source = Join-Path $projectRoot $name
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $releaseRoot }
}

$exePath = Join-Path $releaseRoot 'ForensicKit.exe'
$launcherSource = Join-Path $projectRoot 'scripts\forensickit_launcher.cs'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$exePath" $launcherSource
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exePath)) { throw 'The native launcher build failed.' }

$inventory = @(
    Get-ChildItem -LiteralPath $releaseRoot -File -Recurse |
        Where-Object { $_.FullName -notin @($manifestPath, $manifestDigestPath) } |
        Sort-Object { $_.FullName.Substring($releaseRoot.Length).Replace('\', '/') } |
        ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring($releaseRoot.Length).TrimStart('\').Replace('\', '/')
                size = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
)
$compilerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($compiler).FileVersion
$manifest = [ordered]@{
    release_version = $version
    release_directory = (Split-Path $releaseRoot -Leaf)
    release_type = 'self-contained Windows desktop source-and-runtime package'
    build_time_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    python_runtime = $pythonVersionText
    compiler = ".NET Framework csc $compilerVersion"
    architecture = 'x64'
    signature_status = 'unsigned'
    git_checkpoint = 'see public repository commit and release tag'
    evtx_validation_status = $evtxStatus
    evtx_dependency = 'optional python-evtx==0.8.1 not bundled'
    sample_data = 'synthetic only'
    file_count = $inventory.Count
    files = $inventory
}
$json = $manifest | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($manifestPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($manifestDigestPath, "$manifestHash  release-manifest.json`n", [Text.UTF8Encoding]::new($false))
Compress-Archive -Path (Join-Path $releaseRoot '*') -DestinationPath $archivePath -CompressionLevel Optimal
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($archiveDigestPath, "$archiveHash  $(Split-Path $archivePath -Leaf)`n", [Text.UTF8Encoding]::new($false))

Write-Output "Release folder: $releaseRoot"
Write-Output "Release archive: $archivePath"
Write-Output "Manifest SHA-256: $manifestHash"
Write-Output "Archive SHA-256: $archiveHash"
