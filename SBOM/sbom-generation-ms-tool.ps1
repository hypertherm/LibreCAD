<#
.SYNOPSIS
Generates validated SPDX 2.2 and CycloneDX 1.6 SBOMs for LibreCAD for ProNest.

.DESCRIPTION
Stages only DLL files from the Windows build, generates an SPDX SBOM, enriches each
DLL with its Windows product or file version, merges repository-maintained SPDX
manifests from SBOM/AdditionalAspects, validates the aggregate document, and converts
it to CycloneDX 1.6. When the required command-line tools are not on PATH, the script
downloads their official Windows x64 release binaries into SBOM/tools.
#>

[CmdletBinding()]
param(
    [string]$BuildPath,
    [string]$ProductVersion = $env:VERSION_FULL,
    [string]$ProductName = 'LibreCAD-for-ProNest',
    [string]$ProductSupplier = 'Hypertherm'
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7 or later. Current version: $($PSVersionTable.PSVersion)."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($BuildPath)) {
    $BuildPath = Join-Path $repositoryRoot 'windows'
}
elseif (-not [System.IO.Path]::IsPathRooted($BuildPath)) {
    $BuildPath = Join-Path $repositoryRoot $BuildPath
}

if ([string]::IsNullOrWhiteSpace($ProductVersion)) {
    $ProductVersion = (& git -C $repositoryRoot describe --tags --always --dirty 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ProductVersion)) {
        $versionProject = Get-Content (Join-Path $repositoryRoot 'librecad/src/src.pro')
        $versionLine = $versionProject | Where-Object { $_ -match '^LC_VERSION=' } | Select-Object -First 1
        $ProductVersion = if ($versionLine -match '"([^"]+)"') { $Matches[1] } else { '0.0.0-unknown' }
    }
}
$ProductVersion = $ProductVersion.Trim()

$reportsPath = Join-Path $PSScriptRoot 'reports'
$primaryManifestPath = Join-Path $reportsPath '_manifest/spdx_2.2/manifest.spdx.json'
$aggregateSpdxPath = Join-Path $reportsPath 'aggregate-output/spdx_2.2'
$aggregateManifestPath = Join-Path $aggregateSpdxPath 'manifest.spdx.json'
$additionalAspectsPath = Join-Path $PSScriptRoot 'AdditionalAspects'
$validationOutputPath = Join-Path $reportsPath 'aggregate-validation.json'
$dllBuildPath = Join-Path $reportsPath 'dll-input'
$toolCachePath = Join-Path $PSScriptRoot 'tools'

function Resolve-SbomToolCommand {
    param(
        [Parameter(Mandatory = $true)][string[]]$CommandNames,
        [Parameter(Mandatory = $true)][string]$DownloadUrl,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    foreach ($commandName in $CommandNames) {
        $command = Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $command) {
            return $command.Source
        }
    }

    New-Item $toolCachePath -ItemType Directory -Force | Out-Null
    $toolPath = Join-Path $toolCachePath $FileName
    if (-not (Test-Path $toolPath -PathType Leaf)) {
        Write-Host "Downloading $FileName from its official release." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $toolPath
    }

    if (-not (Test-Path $toolPath -PathType Leaf)) {
        throw "Unable to download '$FileName' from '$DownloadUrl'."
    }

    return $toolPath
}

function Invoke-SbomCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

function Get-SbomManifest {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path -PathType Leaf)) {
        throw "SBOM manifest '$Path' does not exist."
    }
    return Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable
}

function Copy-SbomObject {
    param([Parameter(Mandatory = $true)][hashtable]$Value)
    return $Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
}

function Initialize-SbomCollections {
    param([Parameter(Mandatory = $true)][hashtable]$Manifest)

    foreach ($name in @('packages', 'files', 'relationships')) {
        if (-not $Manifest.ContainsKey($name)) {
            $Manifest[$name] = @()
        }
    }
}

function Add-SbomRelationship {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [Parameter(Mandatory = $true)][hashtable]$Relationship,
        [Parameter(Mandatory = $true)][System.Collections.Generic.HashSet[string]]$Keys
    )

    $key = '{0}|{1}|{2}' -f $Relationship.spdxElementId, $Relationship.relationshipType, $Relationship.relatedSpdxElement
    if ($Keys.Add($key)) {
        $Manifest.relationships += $Relationship
    }
}

function New-DllBuildDrop {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $dllFiles = @(Get-ChildItem $SourcePath -Filter '*.dll' -File -Recurse | Sort-Object FullName)
    if ($dllFiles.Count -eq 0) {
        throw "Build path '$SourcePath' contains no DLL files."
    }

    New-Item $DestinationPath -ItemType Directory -Force | Out-Null
    $dllMetadata = @()
    foreach ($dllFile in $dllFiles) {
        $relativePath = [System.IO.Path]::GetRelativePath($SourcePath, $dllFile.FullName)
        $stagedPath = Join-Path $DestinationPath $relativePath
        New-Item (Split-Path $stagedPath -Parent) -ItemType Directory -Force | Out-Null
        Copy-Item $dllFile.FullName $stagedPath -Force

        $versionInfo = $dllFile.VersionInfo
        $version = @($versionInfo.ProductVersion, $versionInfo.FileVersion) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace($version)) {
            try {
                $version = [System.Reflection.AssemblyName]::GetAssemblyName($dllFile.FullName).Version.ToString()
            }
            catch {
                throw "DLL '$relativePath' has no product, file, or managed assembly version."
            }
        }

        $dllMetadata += [pscustomobject]@{
            RelativePath = $relativePath.Replace('\', '/')
            SourcePath = $dllFile.FullName
            StagedPath = $stagedPath
            Name = $dllFile.Name
            Version = $version.Trim()
            Supplier = if ([string]::IsNullOrWhiteSpace($versionInfo.CompanyName)) {
                'NOASSERTION'
            } else {
                "Organization: $($versionInfo.CompanyName.Trim())"
            }
            Copyright = if ([string]::IsNullOrWhiteSpace($versionInfo.LegalCopyright)) {
                'NOASSERTION'
            } else {
                $versionInfo.LegalCopyright.Trim()
            }
        }
    }

    Write-Host "Staged $($dllMetadata.Count) DLL file(s) for SBOM generation." -ForegroundColor Green
    return $dllMetadata
}

function Add-DllPackageMetadata {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [Parameter(Mandatory = $true)][string]$RootPackageId,
        [Parameter(Mandatory = $true)][object[]]$DllMetadata
    )

    $manifestFiles = @{}
    foreach ($file in @($Manifest.files)) {
        $normalizedPath = $file.fileName -replace '^[.][/\\]', '' -replace '\\', '/'
        $manifestFiles[$normalizedPath.ToLowerInvariant()] = $file
    }

    $existingIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($element in @($Manifest.packages) + @($Manifest.files)) {
        if (-not [string]::IsNullOrWhiteSpace($element.SPDXID)) {
            [void]$existingIds.Add($element.SPDXID)
        }
    }

    foreach ($dll in $DllMetadata) {
        $file = $manifestFiles[$dll.RelativePath.ToLowerInvariant()]
        if ($null -eq $file) {
            throw "Generated SPDX manifest does not contain DLL '$($dll.RelativePath)'."
        }

        $idName = [Regex]::Replace($dll.RelativePath, '[^A-Za-z0-9.-]', '-')
        $pathHash = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData(
                [System.Text.Encoding]::UTF8.GetBytes($dll.RelativePath.ToLowerInvariant())))
        $packageId = "SPDXRef-Dll-$idName-$($pathHash.Substring(0, 12))"
        if (-not $existingIds.Add($packageId)) {
            throw "Generated duplicate SPDX identifier '$packageId' for DLL '$($dll.RelativePath)'."
        }

        $fileSha1 = (Get-FileHash $dll.StagedPath -Algorithm SHA1).Hash.ToLowerInvariant()
        $verificationCode = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA1]::HashData(
                [System.Text.Encoding]::UTF8.GetBytes($fileSha1))).ToLowerInvariant()

        $Manifest.packages += @{
            SPDXID = $packageId
            name = $dll.Name
            versionInfo = $dll.Version
            supplier = $dll.Supplier
            downloadLocation = 'NOASSERTION'
            filesAnalyzed = $true
            packageVerificationCode = @{
                packageVerificationCodeValue = $verificationCode
            }
            licenseConcluded = 'NOASSERTION'
            licenseDeclared = 'NOASSERTION'
            copyrightText = $dll.Copyright
        }
        $Manifest.relationships += @(
            @{
                spdxElementId = $RootPackageId
                relationshipType = 'CONTAINS'
                relatedSpdxElement = $packageId
            },
            @{
                spdxElementId = $packageId
                relationshipType = 'CONTAINS'
                relatedSpdxElement = $file.SPDXID
            }
        )
    }
}

function Merge-AdditionalAspects {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [Parameter(Mandatory = $true)][string]$RootPackageId
    )

    $existingIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($element in @($Manifest.packages) + @($Manifest.files)) {
        if (-not [string]::IsNullOrWhiteSpace($element.SPDXID)) {
            [void]$existingIds.Add($element.SPDXID)
        }
    }

    $relationshipKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($relationship in @($Manifest.relationships)) {
        [void]$relationshipKeys.Add(('{0}|{1}|{2}' -f $relationship.spdxElementId, $relationship.relationshipType, $relationship.relatedSpdxElement))
    }

    if (-not (Test-Path $additionalAspectsPath -PathType Container)) {
        return @()
    }

    $aspectFiles = @(Get-ChildItem $additionalAspectsPath -Filter 'manifest.spdx.json' -Recurse -File |
        Where-Object { $_.FullName -like "*\_manifest\spdx_2.2\manifest.spdx.json" } |
        Sort-Object FullName)

    foreach ($aspectFile in $aspectFiles) {
        $aspect = Get-SbomManifest $aspectFile.FullName
        Initialize-SbomCollections $aspect
        $aspectName = $aspectFile.Directory.Parent.Parent.Name
        $prefix = [Regex]::Replace($aspectName, '[^A-Za-z0-9.-]', '-')
        $idMap = @{}

        foreach ($element in @($aspect.packages) + @($aspect.files)) {
            if ([string]::IsNullOrWhiteSpace($element.SPDXID)) {
                continue
            }
            $suffix = $element.SPDXID -replace '^SPDXRef-', ''
            $candidate = "SPDXRef-$prefix-$suffix"
            $baseCandidate = $candidate
            $index = 1
            while ($existingIds.Contains($candidate)) {
                $candidate = "$baseCandidate-$index"
                $index++
            }
            $idMap[$element.SPDXID] = $candidate
            [void]$existingIds.Add($candidate)
        }

        foreach ($package in @($aspect.packages)) {
            $copy = Copy-SbomObject $package
            $copy.SPDXID = $idMap[$package.SPDXID]
            if ($copy.ContainsKey('hasFiles')) {
                $copy.hasFiles = @($copy.hasFiles | ForEach-Object { if ($idMap.ContainsKey($_)) { $idMap[$_] } else { $_ } })
            }
            $Manifest.packages += $copy
        }
        foreach ($file in @($aspect.files)) {
            $copy = Copy-SbomObject $file
            $copy.SPDXID = $idMap[$file.SPDXID]
            $Manifest.files += $copy
        }

        $aspectRoots = @()
        foreach ($relationship in @($aspect.relationships)) {
            $copy = Copy-SbomObject $relationship
            if ($idMap.ContainsKey($copy.spdxElementId)) { $copy.spdxElementId = $idMap[$copy.spdxElementId] }
            if ($idMap.ContainsKey($copy.relatedSpdxElement)) { $copy.relatedSpdxElement = $idMap[$copy.relatedSpdxElement] }
            if ($relationship.spdxElementId -eq 'SPDXRef-DOCUMENT' -and $relationship.relationshipType -eq 'DESCRIBES') {
                $aspectRoots += $copy.relatedSpdxElement
            }
            else {
                Add-SbomRelationship $Manifest $copy $relationshipKeys
            }
        }
        foreach ($describedId in @($aspect.documentDescribes)) {
            if ($idMap.ContainsKey($describedId)) { $aspectRoots += $idMap[$describedId] }
        }
        foreach ($aspectRoot in @($aspectRoots | Select-Object -Unique)) {
            Add-SbomRelationship $Manifest @{
                spdxElementId = $RootPackageId
                relationshipType = 'DEPENDS_ON'
                relatedSpdxElement = $aspectRoot
            } $relationshipKeys
        }
    }

    return $aspectFiles
}

function Add-CycloneDxCpeEnrichment {
    param(
        [Parameter(Mandatory = $true)][string]$CycloneDxPath,
        [System.IO.FileInfo[]]$AspectFiles
    )

    if (@($AspectFiles).Count -eq 0) {
        return
    }

    $document = Get-Content $CycloneDxPath -Raw | ConvertFrom-Json -AsHashtable
    foreach ($aspectFile in $AspectFiles) {
        $aspect = Get-SbomManifest $aspectFile.FullName
        foreach ($package in @($aspect.packages)) {
            $cpe = @($package.externalRefs | Where-Object {
                $_.referenceCategory -eq 'SECURITY' -and $_.referenceType -eq 'cpe23Type'
            } | Select-Object -First 1)
            if ($cpe.Count -eq 0) { continue }

            $components = @($document.components | Where-Object {
                $_.name -eq $package.name -and $_.version -eq $package.versionInfo
            })
            if ($components.Count -ne 1) {
                throw "Expected one CycloneDX component for '$($package.name)' $($package.versionInfo), found $($components.Count)."
            }
            $components[0].cpe = $cpe[0].referenceLocator
        }
    }
    $document | ConvertTo-Json -Depth 100 | Set-Content $CycloneDxPath -Encoding utf8
}

try {
    $sbomCommand = Resolve-SbomToolCommand -CommandNames @('sbom', 'sbom-tool') `
        -DownloadUrl 'https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-win-x64.exe' `
        -FileName 'sbom-tool-win-x64.exe'
    $cycloneDxCommand = Resolve-SbomToolCommand -CommandNames @('cyclonedx') `
        -DownloadUrl 'https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-win-x64.exe' `
        -FileName 'cyclonedx-win-x64.exe'

    if (-not (Test-Path $BuildPath -PathType Container)) {
        throw "Build path '$BuildPath' does not exist. Build LibreCAD before generating its SBOM."
    }
    if (Test-Path $reportsPath) {
        Remove-Item $reportsPath -Recurse -Force
    }
    New-Item $reportsPath -ItemType Directory -Force | Out-Null
    $dllMetadata = @(New-DllBuildDrop -SourcePath $BuildPath -DestinationPath $dllBuildPath)

    $generateArguments = @(
        'generate', '-b', $dllBuildPath, '-bc', $repositoryRoot,
        '-pn', $ProductName, '-pv', $ProductVersion, '-ps', $ProductSupplier,
        '-nsb', 'https://hypertherm.com/sbom', '-m', $reportsPath,
        '-mi', 'SPDX:2.2', '-li', 'true'
    )
    & $sbomCommand @generateArguments
    $generationExitCode = $LASTEXITCODE
    if (-not (Test-Path $primaryManifestPath -PathType Leaf)) {
        throw "Microsoft SBOM Tool did not create an SPDX manifest (exit code $generationExitCode)."
    }

    # Component detection can return nonzero after producing a usable manifest.
    # Aggregate validation below remains mandatory and authoritative.
    $generatedManifest = Get-SbomManifest $primaryManifestPath
    if (-not $generatedManifest.ContainsKey('SPDXID') -or -not $generatedManifest.ContainsKey('packages')) {
        throw "Microsoft SBOM Tool created an incomplete SPDX manifest (exit code $generationExitCode)."
    }
    if ($generationExitCode -ne 0) {
        Write-Warning "Microsoft SBOM Tool returned $generationExitCode after creating a complete manifest. Continuing to validation."
    }

    $aggregate = $generatedManifest
    Initialize-SbomCollections $aggregate
    $rootPackageId = if (@($aggregate.documentDescribes).Count -gt 0) {
        @($aggregate.documentDescribes)[0]
    } else {
        'SPDXRef-RootPackage'
    }
    Add-DllPackageMetadata -Manifest $aggregate -RootPackageId $rootPackageId -DllMetadata $dllMetadata
    $aspectFiles = @(Merge-AdditionalAspects $aggregate $rootPackageId)

    New-Item $aggregateSpdxPath -ItemType Directory -Force | Out-Null
    $aggregate | ConvertTo-Json -Depth 100 | Set-Content $aggregateManifestPath -Encoding utf8

    & $sbomCommand validate -b $dllBuildPath -m (Split-Path $aggregateSpdxPath -Parent) -mi 'SPDX:2.2' -im -o $validationOutputPath
    $validationExitCode = $LASTEXITCODE
    if (-not (Test-Path $validationOutputPath -PathType Leaf)) {
        throw "Microsoft SBOM Tool did not create a validation report (exit code $validationExitCode)."
    }
    $validation = Get-Content $validationOutputPath -Raw | ConvertFrom-Json
    $validationErrorCount = [int]$validation.ValidationErrors.Count
    if ($validation.Result -ne 'Success' -or $validationErrorCount -ne 0) {
        throw "SBOM validation failed with result '$($validation.Result)', $validationErrorCount validation error(s), and exit code $validationExitCode."
    }
    if ($validationExitCode -ne 0) {
        Write-Warning "Microsoft SBOM Tool returned $validationExitCode after reporting successful validation."
    }

    $safeName = $ProductName -replace '[^A-Za-z0-9._-]', '-'
    $safeVersion = $ProductVersion -replace '[^A-Za-z0-9._-]', '-'
    $spdxOutput = Join-Path $aggregateSpdxPath "${safeName}_v${safeVersion}.spdx.json"
    Move-Item $aggregateManifestPath $spdxOutput -Force

    $cycloneDxOutput = Join-Path $aggregateSpdxPath "${safeName}_v${safeVersion}.cdx.json"
    Invoke-SbomCommand $cycloneDxCommand @(
        'convert', '--input-file', $spdxOutput, '--input-format', 'spdxjson',
        '--output-file', $cycloneDxOutput, '--output-format', 'json', '--output-version', 'v1_6'
    )
    Add-CycloneDxCpeEnrichment $cycloneDxOutput $aspectFiles

    Write-Host "SBOM generation completed for $ProductName $ProductVersion." -ForegroundColor Green
    Write-Host "SPDX: $spdxOutput"
    Write-Host "CycloneDX: $cycloneDxOutput"
}
catch {
    Write-Error "SBOM generation failed: $($_.Exception.Message)"
    exit 1
}
