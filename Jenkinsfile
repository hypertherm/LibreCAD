pipeline 
{
	agent any
	stages 
	{
		stage('Checkout') 
		{
		  steps 
		  {
			bat 'SET'
			deleteDir()
			checkout scm
			stash name: 'source'
		  }
		}

		stage('Install Tools') {
			agent {
				label 'librecad'
			}
			steps {
				bat 'SET'
				script {
					writeFile file: 'Install-RequiredTools.ps1', text: '''
$ErrorActionPreference = 'Stop'

function Add-WingetLinkPath {
    $paths = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\\WinGet\\Links'),
        (Join-Path $env:ProgramFiles 'PowerShell\\7')
    )
    foreach ($path in $paths) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path -PathType Container)) {
            if ($env:PATH -notlike "*$path*") {
                $env:PATH = "$env:PATH;$path"
            }
        }
    }
}

function Install-ToolIfMissing {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$WingetIds
    )

    $existing = Get-Command $Command -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $existing) {
        Write-Host "$Command is already installed at $($existing.Source)" -ForegroundColor Green
        return
    }

    foreach ($id in $WingetIds) {
        Write-Host "Installing $Command using winget package $id" -ForegroundColor Yellow
        winget install --id $id --exact --accept-package-agreements --accept-source-agreements --disable-interactivity
        if ($LASTEXITCODE -eq 0) {
            Add-WingetLinkPath
            $installed = Get-Command $Command -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $installed) {
                Write-Host "$Command installed at $($installed.Source)" -ForegroundColor Green
                return
            }
        }
    }

    throw "Failed to install required tool '$Command' using winget IDs: $($WingetIds -join ', ')."
}

$winget = Get-Command winget -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $winget) {
    throw 'winget is not available on this host. Install App Installer / winget first.'
}

Add-WingetLinkPath

Install-ToolIfMissing -Command 'pwsh' -WingetIds @('Microsoft.PowerShell')
Install-ToolIfMissing -Command 'syft' -WingetIds @('Anchore.Syft')
Install-ToolIfMissing -Command 'sbom-tool' -WingetIds @('Microsoft.SbomTool', 'Microsoft.SBOMTool')
Install-ToolIfMissing -Command 'cyclonedx' -WingetIds @('CycloneDX.cyclonedx-cli')
Install-ToolIfMissing -Command 'cdxgen' -WingetIds @('CycloneDX.cdxgen')
'''
					bat 'powershell -NoProfile -ExecutionPolicy Bypass -File .\\Install-RequiredTools.ps1'
				}
			}
		}

		stage('Build') {
			agent {
				label 'librecad'
			}
			steps 
			{
				bat 'SET'
				deleteDir()
				unstash 'source'
				script
				{
					def LibreCAD = load 'LibreCAD.groovy'
					LibreCAD.Build()
					stash includes: '/**/*.exe', name: 'build_files'
				}
			}
			post
			{
				always
				{
					archiveArtifacts allowEmptyArchive: true, artifacts: '/**/*.exe'
				}
			}
		}
	
		stage('Deploy') 
		{
			agent 
			{
				label 'librecad'
			}
			steps 
			{
				bat 'SET'
				deleteDir()
				// build installer
				unstash 'source'
				unstash 'build_files'
				script
				{
					// copy installer to prod rel
					def LibreCAD = load 'LibreCAD.groovy'
					bat script: 'xcopy "%DEVCOMMON_FOLDER%\\Jenkins\\Binary Management\\VisualC++\\vc_redist.x86.exe" "%WORKSPACE%/redist" /y'
					LibreCAD.BuildInstaller()
					bat 'pwsh -NoProfile -File .\\SBOM\\sbom-generation-ms-tool.ps1'
					def networkPath = CreateNetworkPathForInstaller()
					
					bat script: 'xcopy "' + LibreCAD.GetInstallerPath() + '" "' + networkPath + '" /y'
					bat script: 'xcopy "SBOM\\reports\\aggregate-output\\spdx_2.2\\*.json" "' + networkPath + '" /y'
							
					// create installer link file
					CreateInstallerLinksFile("InstallerLinksLibreCAD.txt", networkPath + "LibreCAD-Installer.exe","")
					stash includes: '/**/InstallerLinks*.txt', name: 'installer'
				}
			}
			post
			{
				always
				{
					bat 'powershell -NoProfile -Command "$zip = Join-Path $env:WORKSPACE \'windows-artifacts.zip\'; if (Test-Path $zip) { Remove-Item $zip -Force }; if (Test-Path (Join-Path $env:WORKSPACE \'windows\')) { Compress-Archive -Path (Join-Path $env:WORKSPACE \'windows\\*\') -DestinationPath $zip -Force }"'
					archiveArtifacts allowEmptyArchive: true, artifacts: 'SBOM/reports/aggregate-output/spdx_2.2/*.json, windows-artifacts.zip'
				}
			}
		}
		stage('Email') 
		{
			steps 
			{
				bat 'SET'
				deleteDir()
				unstash 'source'
				script 
				{
					def notify = load 'notify.groovy'
					if (!env.INSTALLER_TYPE || (env.INSTALLER_TYPE == '')) 
					{
						notify.sendSuccessEmail(false)
					} 
					else 
					{
						unstash 'installer'
						notify.sendSuccessEmail(true)
					}          
				}
			}
			post 
			{	
				always 
				{
					script 
					{
						if (mustCleanWorkspace()) 
						{
							deleteDir()
						}
					}
				}
		  
			}
        }
	}
	post 
	{
	    failure 
		{
			emailext(subject: "${env.PRODUCT_NAME} ${env.VERSION_FULL} - Failure!",
				body: """<p>Check the results for <a href='${currentBuild.absoluteUrl}'>Build #${currentBuild.number}</a>.</p>""",
				mimeType: 'text/html',
				recipientProviders: [[$class: 'DevelopersRecipientProvider']])   
		}
	}
	environment 
	{
		PRODUCT_NAME = 'LibreCAD for ProNest'
		VERSION_BUILD = getVersionBuild()
		INSTALLER_TYPE = getInstallerType()
		RECIPIENTS = 'mtcprogramming, steven.bertken, chris.pollard'
		VERSION_FULL = "2.2.1.${VERSION_BUILD}"
		TARGET_PLATFORM = '32-bit'
		BUILD_DISPLAY_NAME = getDisplayName()
	}
	options 
	{
		buildDiscarder(logRotator(numToKeepStr: '30'))
	}
}
def mustCleanWorkspace()
{
	return false
}

def getVersionBuild()  
{    
  return new Date() - new Date("1/1/2000")
}

def getDisplayName()
{
	def
		displayName = getInstallerType()
	if(displayName != "")
		return displayName
		
	return "(bootleg)"
}
def getInstallerType() 
{
	def 
		branchName = env.BRANCH_NAME.toLowerCase()
		
	if (branchName == "master") 
		return "Release"
	else 
		return "NR"
}
def CreateInstallerLinksFile(linksFileName, pathToInstaller, version)
{
	def body = "<p><a href='" + pathToInstaller + "'>LibreCAD" +  version + "</a>"
	writeFile file: linksFileName, text: body
}
def CreateNetworkPathForInstaller()
{
	def 
		installerType = getInstallerType() 
	if( installerType == 'Release')
		installerType = ''
	else if( installerType == '' || installerType == null)
		installerType = ' NR '
	else
		installerType = ' ' + installerType + ' '
	
	return  '\\\\cam-issvr\\installations\\built by jenkins\\LibreCAD' + installerType +' (' + env.TARGET_PLATFORM + ')\\' + env.BRANCH_NAME + '\\' + "${currentBuild.number}" + '\\'
}