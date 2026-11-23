# Stand-ins for the Az cmdlets, so that the scripts can run without Azure.
# $env:MOCK_STATE (JSON) describes what exists: roles = { name: [actions] }, assignments = [{ role, objId, scope }].
# Every cmdlet that would change something is written to the file $env:MOCK_LOG.

$global:mockState = if ($env:MOCK_STATE) { ConvertFrom-Json $env:MOCK_STATE -AsHashtable } else { @{} }
$global:mockRoles = @{ "Reader" = @(); "Storage Blob Data Reader" = @() }
if ($global:mockState.roles) {
    foreach ($name in $global:mockState.roles.Keys) {
        $global:mockRoles[$name] = @($global:mockState.roles[$name])
    }
}

Add-Type -TypeDefinition @'
namespace Microsoft.Azure.Commands.Resources.Models.Authorization {
    public class PSRoleDefinition {
        public string Name;
        public string Id;
        public string Description;
        public bool IsCustom;
        public string[] Actions;
        public string[] AssignableScopes;
    }
}
'@

function Write-MockCall { param($text) Add-Content -Path $env:MOCK_LOG -Value $text }
function Get-MockRole {
    param($name)
    if ($name -and $global:mockRoles.ContainsKey($name)) {
        $role = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
        $role.Name = $name
        $role.Id = "id-of-$name"
        $role.Actions = $global:mockRoles[$name]
        return $role
    }
}

# read-only cmdlets
function Get-InstalledModule { [pscustomobject]@{ Name = "Az" } }
$global:mockSubscription = "sub-0"
function Get-AzContext { [pscustomobject]@{ Subscription = @{ Id = $global:mockSubscription }; Tenant = @{ Id = "tenant-1" } } }
function Select-AzSubscription { param($SubscriptionId) $global:mockSubscription = $SubscriptionId }
function Set-AzContext { }
function Connect-AzAccount { }
function Get-AzAdUser { [pscustomobject]@{ Id = "user-1"; DisplayName = "Test User" } }
function Get-AzADServicePrincipal { [pscustomobject]@{ Id = "sp-1" } }
function Get-AzADApplication { [pscustomobject]@{ Id = "app-object-1"; AppId = "app-1" } }
function Get-AzRoleDefinition {
    param($Name, $Id, $Scope)
    if ($Id) {
        $Name = $Id -replace '^id-of-', ''
    }
    Get-MockRole -name $Name
}
function Get-AzRoleAssignment {
    param($ObjectId, $RoleDefinitionName, $Scope, [switch]$ExpandPrincipalGroups)
    if ($ExpandPrincipalGroups) {
        return [pscustomobject]@{ Scope = "/"; RoleDefinitionName = "Owner" }
    }
    foreach ($a in $global:mockState.assignments) {
        if ($a.role -eq $RoleDefinitionName -and (-not $ObjectId -or $a.objId -eq $ObjectId)) {
            [pscustomobject]@{ Scope = $a.scope; RoleDefinitionName = $a.role; RoleAssignmentId = "assignment-of-$($a.role)"; DisplayName = "Illumio-CloudSecure-Access" }
        }
    }
}
function Get-AzStorageAccount {
    [pscustomobject]@{ StorageAccountName = "illumiosa1"; Location = "eastus"; NetworkRuleSet = $null }
}

# cmdlets that change something
function New-AzADApplication { param($DisplayName) Write-MockCall "New-AzADApplication $DisplayName"; [pscustomobject]@{ AppId = "app-1" } }
function New-AzADAppCredential { param($ApplicationId) Write-MockCall "New-AzADAppCredential $ApplicationId"; [pscustomobject]@{ SecretText = "s3cr3t" } }
function New-AzADServicePrincipal { param($ApplicationId) Write-MockCall "New-AzADServicePrincipal $ApplicationId"; [pscustomobject]@{ Id = "sp-1" } }
function New-AzRoleAssignment { param($ObjectId, $RoleDefinitionId, $Scope) Write-MockCall "New-AzRoleAssignment $ObjectId $RoleDefinitionId $Scope" }
function New-AzRoleDefinition { param($Role) Write-MockCall "New-AzRoleDefinition $($Role.Name)"; $global:mockRoles[$Role.Name] = $Role.Actions }
function Set-AzRoleDefinition { param($Role) Write-MockCall "Set-AzRoleDefinition $($Role.Name) $($Role.Actions.Count)" }
function Register-AzProviderFeature { param($FeatureName) Write-MockCall "Register-AzProviderFeature $FeatureName" }
function Register-AzResourceProvider { param($ProviderNamespace) Write-MockCall "Register-AzResourceProvider $ProviderNamespace" }
function Remove-AzRoleAssignment { param($InputObject) Write-MockCall "Remove-AzRoleAssignment $($InputObject.RoleAssignmentId)" }
function Remove-AzRoleDefinition { param($InputObject, $Id) Write-MockCall "Remove-AzRoleDefinition $($InputObject.Name)$Id" }
function Remove-AzADApplication { param($ApplicationId, $InputObject) Write-MockCall "Remove-AzADApplication $ApplicationId$($InputObject.AppId)" }
function Update-AzStorageAccountNetworkRuleSet { param($Name, $IPRule) Write-MockCall "Update-AzStorageAccountNetworkRuleSet $Name $($IPRule.IPAddressOrRange)" }
function Invoke-WebRequest {
    param($Uri, $Headers, $Method, $Body, $OutFile)
    if ($OutFile) {
        # the dataplane metadata download
        Set-Content -Path $OutFile -Value '{"regions":{"eastus":"us-east"},"ipGroups":{"us-east":{"ips":["192.0.2.10","192.0.2.11"]}}}'
        return
    }
    # keys sorted, so that the same payload always gives the same line
    $payLoad = ConvertFrom-Json $Body -AsHashtable
    $sorted = [ordered]@{}
    foreach ($key in ($payLoad.Keys | Sort-Object)) {
        $sorted[$key] = $payLoad[$key]
    }
    Write-MockCall "Invoke-WebRequest $Uri $($Headers['X-Tenant-Id']) $(ConvertTo-Json $sorted -Compress)"
    [pscustomobject]@{ StatusCode = 200 }
}
