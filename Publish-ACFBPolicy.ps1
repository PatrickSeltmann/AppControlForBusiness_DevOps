#Requires -Version 7.0   # Make sure we run on PowerShell 7 or newer

<#
.SYNOPSIS
Publishes App Control for Business (ACfB) policies to Intune:
- Signs local policy XML files (Base_*.xml / Supplemental_*.xml) with a certificate,
- Restores the original VersionEx after signing and compares local and remote version on it (signer tool reset it),
- Creates or updates the matching Intune configuration policy via Microsoft Graph.

.DESCRIPTION
This script automates the full ACfB policy publishing flow. It scans a source folder for
policy XMLs with the naming pattern Base_*.xml or Supplemental_*.xml, copies them to an output folder,
signs them using a .cer/.crt certificate (stored in the 'certs' folder), and uploads the signed XML to Intune using the Microsoft Graph API.

Key behaviors:
- Dual auth mode:
  • CI/CD (non-interactive): Use -AccessToken (e.g., from Azure DevOps OIDC service connection).
  • Manual (interactive): Prompt using Microsoft.Graph.Authentication with the required scope.
- update logic:
  The script reads the currently deployed XML from Intune and compares versions/content:
    • Update if local VersionEx > remote VersionEx,
- Safe writes:
  The script writes the signed XML to the output folder and uses that file for upload, so you
  can audit, commit, or archive the exact payload that Intune receives.

Requirements:
- PowerShell 7+ (see #Requires -Version 7.0).
- Microsoft.Graph PowerShell (module Microsoft.Graph.Authentication; auto-install on demand).
- A signing certificate file (.cer or .crt) accessible on the machine/repo.
- Intune / Graph permissions:
  • Scope DeviceManagementConfiguration.ReadWrite.All (for manual interactive login)
  • Or an app/workload identity with equivalent permissions and consent (for CI/CD).

Folders:
- $PolicyRootDir: unsigned XML templates (Base_*.xml / Supplemental_*.xml)
- $OutputPolicyDir: signed XML copies (final upload payloads)
- $CertFolder: contains .cer/.crt to sign with (first match is used)

API:
- Uses Microsoft Graph beta endpoints for ACfB configuration policies.
- Template families:
    Base:          endpointSecurityApplicationControl
    Supplemental:  endpointSecurityApplicationControlSupplementalPolicy
- The script targets the Intune setting definition “..._xml” to embed the full policy XML string.

Error handling & logging:
- The script stops on errors (ErrorActionPreference = 'Stop').
- If Graph returns an error with a JSON body, it is printed for troubleshooting.
- Logs source/local/remote VersionEx values to help diagnose version logic.

.PARAMETER PolicyRootDir
Path to the folder containing unsigned policy XML files (Base_*.xml / Supplemental_*.xml).
Default: .\Policies\unsigned_original

.PARAMETER OutputPolicyDir
Path to the folder where signed policy XML copies will be written (and uploaded from).
Default: .\Policies\signed

.PARAMETER CertFolder
Path to the folder containing .cer or .crt files used for signing.
The first found match is used.
Default: .\Certs

.PARAMETER TenantId
Optional tenant ID hint for interactive (manual) Connect-MgGraph.
Ignored when -AccessToken is provided (CI/CD).

.PARAMETER AccessToken
Optional bearer token for non-interactive (CI/CD) authentication with Connect-MgGraph -AccessToken.
If provided, the script will not prompt for interactive login.

.PARAMETER DryRun
If set, the script only prints what it would do (CREATE/UPDATE policy) without uploading to Intune.

.EXAMPLE
# Manual (interactive) run with default folders and interactive Graph login.
pwsh ./Publish-ACFBPolicy.ps1 `
  -PolicyRootDir .\Policies\unsigned_original `
  -OutputPolicyDir .\Policies\signed `
  -CertFolder .\Certs

.EXAMPLE
# Manual run for a specific tenant (interactive login).
pwsh ./Publish-ACFBPolicy.ps1 `
  -TenantId "00000000-0000-0000-0000-000000000000"

.EXAMPLE
# CI/CD (Azure DevOps): pass the access token obtained in a prior AzureCLI@2 step.
pwsh ./Publish-ACFBPolicy.ps1 `
  -PolicyRootDir "$(Build.SourcesDirectory)\Policies\unsigned_original" `
  -OutputPolicyDir "$(Build.SourcesDirectory)\Policies\signed" `
  -CertFolder "$(Build.SourcesDirectory)\Certs" `
  -AccessToken "$(secret)"

.EXAMPLE
# Dry run (no upload) to see what would be created/updated.
pwsh ./Publish-ACFBPolicy.ps1 -DryRun

.NOTES
- PowerShell 7+ is required. On Windows, run with “pwsh” (not “powershell”).
- If your signing helper resets VersionEx, this script restores it from the unsigned source.
- Make sure Add-SignerRule is available on the PATH (or dot-source your custom implementation).
- If you want to commit the signed outputs back to your repo, do so after the script finishes.

.LINK
Microsoft Graph docs (Intune configuration policies):
https://learn.microsoft.com/mem/intune/configuration/device-profile-create
#>

param (
  [string]$PolicyRootDir   = ".\Policies\unsigned_original",
  [string]$OutputPolicyDir = ".\Policies\signed",
  [string]$CertFolder      = ".\Certs",
  [string]$TenantId        = $null,
  [string]$AccessToken,
  [switch]$DryRun
)

begin {
  $ErrorActionPreference = 'Stop'

  function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
      Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
    }
    Import-Module $Name -ErrorAction Stop
  }

  function Connect-MSGraphSmart {
    param([string]$Token, [string]$Tenant)
    Ensure-Module -Name Microsoft.Graph.Authentication

    if ($Token) {
      $secureToken = ConvertTo-SecureString -String $Token -AsPlainText -Force
      Connect-MgGraph -AccessToken $secureToken -NoWelcome | Out-Null
      return
    }

    $scopes = @('DeviceManagementConfiguration.ReadWrite.All')
    if ($Tenant) {
      Connect-MgGraph -Scopes $scopes -TenantId $Tenant -NoWelcome | Out-Null
    } else {
      Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
    }
  }

  function Load-PolicyXml {
    param([string]$Path)
    try {
      $rawXml = Get-Content -Path $Path -Raw -Encoding UTF8
      [xml]$xml = $rawXml
      return @{ Xml = $xml; Raw = $rawXml }
    } catch {
      Write-Error "Failed to load XML from '$Path': $($_.Exception.Message)"
      return $null
    }
  }

  function Get-VersionText {
    param([string]$RawXml)
    $m = [regex]::Match($RawXml, 'VersionEx\s*=\s*"([^"]+)"', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($RawXml, '<VersionEx>\s*([^<]+)\s*</VersionEx>', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
  }

  # Connect to Microsoft Graph (token preferred)
  Connect-MSGraphSmart -Token $AccessToken -Tenant $TenantId
  $MgContext = Get-MgContext
  if (-not $MgContext) { throw "Failed to connect to Microsoft Graph." }
  Write-Host "Connected to Graph. TenantId=$($MgContext.TenantId)"

  # Paths
  if (-not (Test-Path $PolicyRootDir))  { throw "Directory '$PolicyRootDir' does not exist." }
  if (-not (Test-Path $OutputPolicyDir)) { New-Item -Path $OutputPolicyDir -ItemType Directory | Out-Null }
  if (-not (Test-Path $CertFolder))     { throw "Cert folder '$CertFolder' does not exist." }

  # Ensure signer helper exists
  if (-not (Get-Command Add-SignerRule -ErrorAction SilentlyContinue)) {
    throw "Add-SignerRule not found on this machine/agent."
  }

  $NamePattern = [regex]'(?i)^(Base|Supplemental)_(.+)\.xml$'
  $PolicyFiles = Get-ChildItem -Path $PolicyRootDir -Recurse -Filter *.xml |
                 Where-Object { $NamePattern.IsMatch($_.Name) }

  if (-not $PolicyFiles) {
    Write-Warning "No policies found in $PolicyRootDir."
    return
  }
}

process {
  foreach ($PolicyFile in $PolicyFiles) {
    $match = $NamePattern.Match($PolicyFile.Name)
    $PolicyType = $match.Groups[1].Value
    $PolicyKey  = $match.Groups[2].Value
    $PolicyName = "($PolicyType) - $PolicyKey"

    switch ($PolicyType) {
      "Base" {
        $TemplateId = "4321b946-b76b-4450-8afd-769c08b16ffc_1"
        $TemplateFamily = "endpointSecurityApplicationControl"
        $TemplateDisplayName = "App Control for Business"
        $SignSupplemental = $true
      }
      "Supplemental" {
        $TemplateId = "08441ae9-e0c0-4e57-8e8b-6e72405cd64f_1"
        $TemplateFamily = "endpointSecurityApplicationControlSupplementalPolicy"
        $TemplateDisplayName = "App Control for Business - Supplemental"
        $SignSupplemental = $false
      }
      default {
        Write-Warning "Unknown policy type: $PolicyType skipping."
        continue
      }
    }

    Write-Host ""
    Write-Host "Processing policy: $PolicyName" -ForegroundColor Cyan

    # Read source version (before signing)
    $SourceXmlRaw = Get-Content -Path $PolicyFile.FullName -Raw -Encoding UTF8
    $SourceVersionText = Get-VersionText $SourceXmlRaw
    if (-not $SourceVersionText) { $SourceVersionText = '0.0.0.0' }

    # Sign
    $Cert = Get-ChildItem -Path $CertFolder -Recurse -Include *.cer, *.crt -File | Select-Object -First 1
    if (-not $Cert) { throw "No .cer/.crt found in '$CertFolder'." }

    $SignedPath = Join-Path $OutputPolicyDir $PolicyFile.Name
    Copy-Item -Path $PolicyFile.FullName -Destination $SignedPath -Force

    $beforeHash = (Get-FileHash -Algorithm SHA256 -Path $SignedPath).Hash
    Add-SignerRule -FilePath $SignedPath -CertificatePath $Cert.FullName -Update:$true -Supplemental:$SignSupplemental
    $afterHash  = (Get-FileHash -Algorithm SHA256 -Path $SignedPath).Hash
    if ($beforeHash -eq $afterHash) { throw "Signing did not change '$SignedPath'." }

    # Restore VersionEx after signing
    [xml]$SignedXml = Get-Content -Path $SignedPath -Raw -Encoding UTF8
    if ($SignedXml.SiPolicy.VersionEx) {
      $SignedXml.SiPolicy.VersionEx = $SourceVersionText
    } else {
      $newNode = $SignedXml.CreateElement("VersionEx", $SignedXml.SiPolicy.NamespaceURI)
      $newNode.InnerText = $SourceVersionText
      [void]$SignedXml.SiPolicy.InsertAfter($newNode, $SignedXml.SiPolicy.FirstChild)
    }
    # PS7: utf8 is UTF-8 without BOM
    $SignedXml.OuterXml | Set-Content -Path $SignedPath -Encoding utf8

    # Local version from signed XML
    $LocalPolicy = Load-PolicyXml -Path $SignedPath
    if (-not $LocalPolicy) { continue }
    $LocalXmlRaw = $LocalPolicy.Raw
    $LocalVersionText = Get-VersionText $LocalXmlRaw
    if (-not $LocalVersionText) { $LocalVersionText = '0.0.0.0' }
    try { [version]$LocalVersion = $LocalVersionText } catch { $LocalVersion = [version]'0.0.0.0' }

    # Query existing policy
    $UriGET = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$TemplateFamily' and name eq '$PolicyName'"
    $Existing = Invoke-MgGraphRequest -Method GET -Uri $UriGET
    $ExistingPolicy = $Existing.value | Select-Object -First 1

    $DoCreate = -not $ExistingPolicy
    $DoUpdate = $false
    $RemoteVersion = [version]"0.0.0.0"
    $RemoteXmlRaw = $null

    if ($ExistingPolicy) {
      $PolicyId = $ExistingPolicy.id
      $UriSettings = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$PolicyId/settings"
      $Settings = Invoke-MgGraphRequest -Method GET -Uri $UriSettings

      foreach ($v in $Settings.value) {
        $choice = $v.settingInstance.choiceSettingValue
        if ($choice -and $choice.children) {
          $xmlChild = $choice.children | Where-Object {
            $_.settingDefinitionId -eq "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml"
          } | Select-Object -First 1
          if ($xmlChild -and $xmlChild.simpleSettingValue.value) {
            $RemoteXmlRaw = [string]$xmlChild.simpleSettingValue.value
            break
          }
        }
        if (-not $RemoteXmlRaw -and $v.settingInstance.simpleSettingValue.value) {
          $candidate = [string]$v.settingInstance.simpleSettingValue.value
          if ($candidate -match '<SiPolicy') { $RemoteXmlRaw = $candidate; break }
        }
      }

      if ($RemoteXmlRaw) {
        $RemoteVersionText = Get-VersionText $RemoteXmlRaw
        if (-not $RemoteVersionText) { $RemoteVersionText = '0.0.0.0' }
        try { [version]$RemoteVersion = $RemoteVersionText } catch { }
      }

      if ($LocalVersion -gt $RemoteVersion) { $DoUpdate = $true }
            else {
        Write-Host "Versions match or remote is newer - no update required." -ForegroundColor Yellow
        continue
      }
    }

    if ($DryRun) {
      Write-Host -NoNewline "[DRY RUN] Would "
      if ($DoCreate) { Write-Host "CREATE $PolicyName" -ForegroundColor Cyan }
      elseif ($DoUpdate) { Write-Host "UPDATE $PolicyName" -ForegroundColor Cyan }
      continue
    }

    # Payload
    $SettingsPayload = @(
      @{
        "@odata.type"   = "#microsoft.graph.deviceManagementConfigurationSetting"
        settingInstance = @{
          "@odata.type"                    = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
          settingDefinitionId              = "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions"
          choiceSettingValue               = @{
            "@odata.type"                 = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
            value                         = "device_vendor_msft_policy_config_applicationcontrol_configure_xml_selected"
            children                      = @(
              @{
                "@odata.type"                    = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                settingDefinitionId              = "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml"
                simpleSettingValue               = @{
                  "@odata.type"                 = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                  value                         = [string]$LocalXmlRaw
                  settingValueTemplateReference = @{
                    settingValueTemplateId = "88f6f096-dedb-4cf1-ac2f-4b41e303adb5"
                  }
                }
                settingInstanceTemplateReference = @{
                  settingInstanceTemplateId = "4d709667-63d7-42f2-8e1b-b780f6c3c9c7"
                }
              }
            )
            settingValueTemplateReference = @{
              settingValueTemplateId = "b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3"
            }
          }
          settingInstanceTemplateReference = @{
            settingInstanceTemplateId = "1de98212-6949-42dc-a89c-e0ff6e5da04b"
          }
        }
      }
    )

    $Payload = @{
      name              = $PolicyName
      description       = "Uploaded at $(Get-Date -Format 'yyyy-MM-dd HH:mm') via Azure DevOps Pipeline"
      platforms         = "windows10"
      technologies      = "mdm"
      roleScopeTagIds   = @("0")
      templateReference = @{
        "@odata.type"          = "microsoft.graph.deviceManagementConfigurationPolicyTemplateReference"
        templateId             = $TemplateId
        templateFamily         = $TemplateFamily
        templateDisplayName    = $TemplateDisplayName
        templateDisplayVersion = "Version 1"
      }
      settings          = $SettingsPayload
    }

    try {
      if ($DoUpdate) {
        $UriUpdate = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')"
        Invoke-MgGraphRequest -Method PUT -Uri $UriUpdate -Body $Payload -ContentType "application/json"
        Write-Host "Updated: $PolicyName" -ForegroundColor Green
      } elseif ($DoCreate) {
        $UriCreate = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
        Invoke-MgGraphRequest -Method POST -Uri $UriCreate -Body $Payload -ContentType "application/json"
        Write-Host "Created: $PolicyName" -ForegroundColor Green
      }
    } catch {
      Write-Error "Failed to process '$PolicyName': $($_.Exception.Message)"
      if ($_.Exception.Response -and $_.Exception.Response.Content) {
        try {
          $errorContent = $_.Exception.Response.Content.ReadAsStringAsync().Result
          Write-Host ("Graph API Error Content:`n" + $errorContent) -ForegroundColor Red
        } catch { }
      }
    }
  }
}

end {
  Disconnect-MgGraph | Out-Null
  Write-Host ""
  Write-Host "Script execution completed." -ForegroundColor DarkGray
}

