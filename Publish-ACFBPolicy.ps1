#Requires -Version 7.0
<#
.SYNOPSIS
  Processes App Control for Business (ACfB) Base and Supplemental Policies from disk or git repository,
  signs them, and uploads them to Microsoft Intune using Microsoft Graph API.
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
