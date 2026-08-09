param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"
if ($Version -ne "manual" -and $Version -notmatch '^hub-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$') {
    throw "Unsafe hub release version: $Version"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$binary = Join-Path $root "target\release\hacash-l2-hub.exe"
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Missing release binary: $binary"
}

$dist = Join-Path $root "dist-hub"
$packageName = "hpay-fast-pay-hub-windows-x64"
$package = Join-Path $dist $packageName
$archive = Join-Path $dist "$packageName-$Version.zip"

if (-not $dist.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean a dist path outside the repository"
}
if (Test-Path -LiteralPath $dist) {
    Remove-Item -LiteralPath $dist -Recurse -Force
}
New-Item -ItemType Directory -Path $package -Force | Out-Null

Copy-Item -LiteralPath $binary -Destination (Join-Path $package "hacash-l2-hub.exe")
Copy-Item -LiteralPath (Join-Path $root "README-HUB.txt") -Destination (Join-Path $package "README.txt")
Copy-Item -LiteralPath (Join-Path $root "l2-hub.example.ini") -Destination $package
Copy-Item -LiteralPath (Join-Path $root "SECURITY.md") -Destination $package
Copy-Item -LiteralPath (Join-Path $root "NETWORK-GLOBAL.md") -Destination $package

$commit = "unknown"
try {
    $candidate = (& git -C $root rev-parse HEAD 2>$null).Trim()
    if ($candidate -match '^[0-9a-f]{40}$') { $commit = $candidate }
} catch {}
$newline = [Environment]::NewLine
[IO.File]::WriteAllText((Join-Path $package "VERSION.txt"), "$Version$newline", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $package "SOURCE-COMMIT.txt"), "$commit$newline", [Text.UTF8Encoding]::new($false))

Compress-Archive -LiteralPath $package -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$archive.sha256", "$hash  $([IO.Path]::GetFileName($archive))$newline", [Text.UTF8Encoding]::new($false))
Write-Output $archive
