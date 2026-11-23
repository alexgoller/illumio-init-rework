param($sid = "", $tid = "", $clientId = "", $name = "",
    [Single][validateRange(1, 1000)]$secretExpirationDays = 365,
    $serviceAccountKey = "", $serviceAccountToken = "", $csTenantId = "", $url = "",
    [String[]]$storageAccounts, [switch]$azfw, [switch]$remove, [switch]$nsg, [switch]$rotateSecret,
    [switch]$whitelistStorageAccounts, $dataplaneMetadataPath = "",
    $existingAppId = "", $existingAppSecret = "",
    $nsgRoleId = "", $nsgRoleName = "",
    [switch]$DryRun, [ValidateSet("az", "ps")][string]$Generate, $OutFile = "")

# Input from user
$subscriptionId = $sid
$tenantId = $tid

# Global variables.
$scope = ""
$AppName = ""

$ErrorActionPreference = "Stop"

New-Variable -Name DefaultAppName -Value "Illumio-CloudSecure-Access" -Option Constant
New-Variable -Name RoleName -Value "Illumio Firewall Administrator" -Option Constant
New-Variable -Name IllumioNSGRoleName -Value "Illumio Network Security Administrator" -Option Constant
New-Variable -Name SubscriptionScopePrefix -Value "/subscriptions" -Option Constant
New-Variable -Name TenantScopePrefix -Value "/providers/Microsoft.Management/managementGroups" -Option Constant
New-Variable -Name ReaderRole -Value "Reader" -Option Constant
New-Variable -Name StorageReaderRole -Value "Storage Blob Data Reader" -Option Constant
New-Variable -Name DataplaneMetadataUrl -Value "https://cloudsecure-integration-templates.s3.us-west-2.amazonaws.com/dataplane-ips-dev.json" -Option Constant
New-Variable -Name CredentialsEndpoint -Value "/api/v1/integrations/cloud_credentials" -Option Constant
New-Variable -Name EventsEndpoint -Value "/api/v1/integrations/cloud/azure/accounts/{account_id}/event" -Option Constant
New-Variable -Name DefaultErrorCode -Value "APP_REGISTRATION_FAILED" -Option Constant
# stands in for the service principal of an app that -DryRun did not create
New-Variable -Name PlannedPrincipalId -Value "<new-service-principal-id>" -Option Constant
New-Variable -Name FirewallRoleActions -Option Constant -Value @(
    "Microsoft.Network/azurefirewalls/read",
    "Microsoft.Network/azurefirewalls/learnedIPPrefixes/action",
    "Microsoft.Network/azureFirewalls/applicationRuleCollections/write",
    "Microsoft.Network/azureFirewalls/applicationRuleCollections/delete",
    "Microsoft.Network/azureFirewalls/applicationRuleCollections/read",
    "Microsoft.Network/azurefirewalls/providers/Microsoft.Insights/logDefinitions/read",
    "Microsoft.Network/azureFirewalls/natRuleCollections/write",
    "Microsoft.Network/azureFirewalls/natRuleCollections/read",
    "Microsoft.Network/azureFirewalls/natRuleCollections/delete",
    "Microsoft.Network/azureFirewalls/networkRuleCollections/read",
    "Microsoft.Network/azureFirewalls/networkRuleCollections/write",
    "Microsoft.Network/azureFirewalls/networkRuleCollections/delete",
    "Microsoft.Network/azureFirewallFqdnTags/read",
    "Microsoft.Network/azurefirewalls/providers/Microsoft.Insights/metricDefinitions/read",
    "Microsoft.Network/firewallPolicies/read",
    "Microsoft.Network/firewallPolicies/write",
    "Microsoft.Network/firewallPolicies/join/action",
    "Microsoft.Network/firewallPolicies/certificates/action",
    "Microsoft.Network/firewallPolicies/delete",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/read",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/delete",
    "Microsoft.Network/firewallPolicies/ruleGroups/read",
    "Microsoft.Network/firewallPolicies/ruleGroups/write",
    "Microsoft.Network/firewallPolicies/ruleGroups/delete",
    "Microsoft.Network/ipGroups/read",
    "Microsoft.Network/ipGroups/write",
    "Microsoft.Network/ipGroups/validate/action",
    "Microsoft.Network/ipGroups/updateReferences/action",
    "Microsoft.Network/ipGroups/join/action",
    "Microsoft.Network/ipGroups/delete"
)
New-Variable -Name NSGRoleActions -Option Constant -Value @(
    "Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Network/networkSecurityGroups/join/action",
    "Microsoft.Network/networkSecurityGroups/defaultSecurityRules/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Network/networksecuritygroups/providers/Microsoft.Insights/diagnosticSettings/read",
    "Microsoft.Network/networksecuritygroups/providers/Microsoft.Insights/diagnosticSettings/write",
    "Microsoft.Network/networksecuritygroups/providers/Microsoft.Insights/logDefinitions/read",
    "Microsoft.Network/networkWatchers/securityGroupView/action",
    "Microsoft.Network/networkSecurityGroups/*",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/networkInterfaces/write",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/write",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Authorization/locks/*",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Network/virtualNetworks/subnets/join/action",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/publicIPAddresses/join/action"
)

# changes that -DryRun reported and did not make
$plannedChanges = [System.Collections.ArrayList]@()

# Makes a change in Azure or CloudSecure. With -DryRun the change is only reported and $dryRunResult is returned.
function Invoke-Change {
    param (
        [string]$description,
        [scriptblock]$action,
        $dryRunResult = $null
    )

    if ($DryRun) {
        Write-Host "[dry-run] would: $description" -ForegroundColor Cyan
        [Void]$plannedChanges.Add($description)
        # "return $null" would add a $null to the output of the calling function
        if ($null -ne $dryRunResult) {
            $dryRunResult
        }
        return
    }
    & $action
}


function remove-Illumio-App {
    param (
        $ctx
    )
    try {
        foreach ($c in Get-AzContext -ListAvailable) {
            if ($c.Tenant.Id -eq $ctx.Tenant.Id) {
                foreach ($assignment in Get-AzRoleAssignment -RoleDefinitionName "Storage Blob Data contributor") {
                    if ($assignment.DisplayName -eq $AppName) {
                        Write-Host "Removing storage role assignment $( $assignment.RoleAssignmentId )`n"
                        Invoke-Change -description "Remove storage role assignment $( $assignment.RoleAssignmentId )" -action {
                            Remove-AzRoleAssignment -InputObject $assignment | Out-Null
                        }
                    }
                }
                $subsRoleName = "$RoleName-$( $c.Subscription.Id )"
                foreach ($assignment in Get-AzRoleAssignment -RoleDefinitionName $subsRoleName -DefaultProfile $c) {
                    Write-Host "Removing role assignment $( $assignment.RoleAssignmentId )`n"
                    try {
                        Invoke-Change -description "Remove role assignment $( $assignment.RoleAssignmentId )" -action {
                            Remove-AzRoleAssignment -InputObject $assignment -DefaultProfile $c  | Out-Null
                        }
                    }
                    catch {
                    }
                }

                $r = Get-AzRoleDefinition -Name $subsRoleName -DefaultProfile $c -WarningAction Ignore
                if ($r) {
                    Write-Host "Removing role '$subsRoleName'`n"
                    try {
                        Invoke-Change -description "Remove role '$subsRoleName'" -action {
                            Remove-AzRoleDefinition -InputObject $r -DefaultProfile $c -Force -WarningAction Ignore | Out-Null
                        }
                    }
                    catch {
                    }
                }
            }
        }

        foreach ($app in Get-AzADApplication -DisplayName $AppName) {
            Write-Host "Removing app '$( $app.Id )'`n"
            Invoke-Change -description "Remove app registration '$AppName' ($( $app.AppId ))" -action {
                Remove-AzADApplication -ApplicationId $app.AppId
            }
        }
    }
    catch {
        Write-Host "Error: $_"
    }
}

function get-StorageScopes {
    param (
        $storageAccounts,
        $ctx
    )

    if (!$storageAccounts) {
        return
    }

    Write-Host "Using storage accounts $storageAccounts`n"

    # remove duplicates
    $storageAccounts = $storageAccounts | Select-Object -Unique
    $result = [System.Collections.ArrayList]@()
    try {
        $c = Get-AzContext
        $sas = Get-AzStorageAccount -DefaultProfile $c

        foreach ($requestedSA in $storageAccounts) {
            foreach ($sa in $sas) {
                $saName = $requestedSA -split "/"
                $saName = $saName[-1]
                if ($sa.StorageAccountName -eq $saName) {
                    [Void]$result.Add("$( $requestedSA )")
                }
            }
        }
    }
    catch {
        Write-Host "Error: $_"
    }

    return $result | Select-Object -Unique
}

function Confirm-User-Permission-For-Scope {
    param (
        $scope
    )
    try {
        $user = Get-AzAdUser -SignedIn
        # -ExpandPrincipalGroups includes roles the user holds through (nested) group membership. It cannot be
        # combined with -Scope, so it lists the assignments of the current subscription, which must be selected first.
        $roles = Get-AzRoleAssignment -ObjectId $user.Id -ExpandPrincipalGroups -WarningAction Ignore
        $hasPermission = $false
        Write-Host "Checking if user has Owner or User Access Administrator Role on scope $scope`n"
        foreach ($r in $roles) {
            # only assignments on the scope itself or inherited from above cover the whole scope;
            # management groups listed for a subscription are always its parents
            $coversScope = $r.Scope -eq $scope -or $r.Scope -eq "/" -or
                ($scope.StartsWith("$SubscriptionScopePrefix/") -and $r.Scope.StartsWith("$TenantScopePrefix/", [StringComparison]::OrdinalIgnoreCase))
            if (-not $coversScope) {
                continue
            }
            if ($r.RoleDefinitionName -eq "Owner" -or $r.RoleDefinitionName -eq "User Access Administrator") {
                $hasPermission = $true
                break
            }
        }
        if ($hasPermission) {
            Write-Host "User has permission to create Ad Application on the scope $scope`n"
        }
        else {
            throw "User $($user.DisplayName) does not have the required permission to proceed with Azure Onboarding. User needs to be 'Owner' or 'UserAccess Administrator' role to proceed with Onboarding."
        }
    }
    catch {
        Write-Error "Error: $_"
        return $_
    }
}

# Returns $true if the role is assigned to the principal on the scope, either directly or inherited from a parent scope
function Test-Role-Assigned {
    param (
        $scope,
        $role,
        $objId
    )

    # with -DryRun a new app has no principal yet, so it cannot hold any role
    if ($objId -eq $PlannedPrincipalId) {
        return $false
    }

    try {
        # the result also contains assignments on child scopes (e.g. resource groups), which do not cover the whole scope
        $assignments = Get-AzRoleAssignment -ObjectId $objId -RoleDefinitionName $role -Scope $scope -WarningAction Ignore
        foreach ($a in $assignments) {
            if (-not $a.Scope.StartsWith("$scope/", [StringComparison]::OrdinalIgnoreCase)) {
                Write-Host "Role $role is already assigned to $objId on scope $($a.Scope). Skipping`n" -ForegroundColor Yellow
                return $true
            }
        }
    }
    catch {
        # not fatal: the assignment itself reports a real problem, or a conflict if the role is already assigned
        Write-Host "Could not check for an existing assignment of role $role on scope $scope. $_`n" -ForegroundColor Yellow
    }
    return $false
}

function Add-Role-To-Scope {
    param (
        $scope,
        $role,
        $objId
    )

    try {
        if (Test-Role-Assigned -scope $scope -role $role -objId $objId) {
            return
        }

        Invoke-Change -description "Assign role '$role' to the app principal $objId on scope $scope" -action {
            #fetching role definition id
            $roleDef = Get-AzRoleDefinition -Name $role -WarningAction Ignore

            Write-Host "Assigning role $role to the app principal $objId on scope $scope"
            New-AzRoleAssignment -ObjectId $objId -RoleDefinitionId $roleDef.Id -Scope $scope | Out-Null
        }
    }
    catch {
        # a conflict means the role is already assigned to the principal on this scope
        if ($_.Exception.Message.Contains("Conflict")) {
            Write-Host "Role $role is already assigned to $objId on scope $scope. Skipping`n" -ForegroundColor Yellow
            return
        }
        Write-Host "Error Occured: $_" -ForegroundColor "Red"
        return $_
    }
}

function install-Illumio-App {
    param (
        $ctx,
        $existingAppId,
        $existingAppSecret
    )

    try {
        $storageScopes = get-StorageScopes -storageAccounts $storageAccounts -ctx $ctx
        if ($storageAccounts -and !$storageScopes) {
            throw "Please provide a valid storage account name"
        }
        if ($sid -ne "") {
            $subscriptionId = $ctx.Subscription.Id
        }

        if ($azfw) {
            # Register features
            foreach ($feature in @("AFWEnableNetworkRuleNameLogging", "AFWEnableStructuredLogs")) {
                Write-Host "Registering $feature`n"
                Invoke-Change -description "Register feature Microsoft.Network/$feature" -action {
                    Register-AzProviderFeature -FeatureName $feature -ProviderNamespace "Microsoft.Network" | Out-null
                }
            }

            Write-Host "Registering Microsoft.Network`n"
            Invoke-Change -description "Register resource provider Microsoft.Network" -action {
                Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-null
            }
        }

        if ($existingAppId -and $existingAppSecret) {
            Write-Host "Using existing Azure Active Directory App Registration $existingAppId`n"
            $appId = $existingAppId
            $secretText = $existingAppSecret
            $appPrincipal = Get-AzADServicePrincipal -ApplicationId $appId
            if (!$appPrincipal) {
                throw "Unable to find Service Principal for the provided AppId $appId"
            }
        }
        else {
            # Create AD App
            Write-Host "Creating Azure Active Directory App Registration`n"
            $illumioApp = Invoke-Change -description "Create app registration '$AppName'" -dryRunResult @{ AppId = "<new-app-id>" } -action {
                New-AzADApplication -DisplayName $AppName
            }

            $appId = $illumioApp.AppId

            $appSecret = New-Application-Secret($appId)
            if (-not $appSecret) {
                throw "error generating secret"
            }
            $secretText = $appSecret.SecretText

            Write-Host "Creating Azure Active Directory App Principal`n"
            $appPrincipal = Invoke-Change -description "Create service principal for app $appId" -dryRunResult @{ Id = $PlannedPrincipalId } -action {
                New-AzADServicePrincipal -ApplicationId $appId -Description "Illumio App Service Principal"
            }
        }

        $err = Add-Role-To-Scope -scope $scope -role $ReaderRole -objId $appPrincipal.Id
        if ($err) {
            Write-Host "Unable to assign $($ReaderRole) to $($appPrincipal.Id) on scope $($scope) due to err $err" -Foreground Red
            throw $err
        }

        # checking and providing storage access if storage accounts are passed.
        if ($storageAccounts) {
            Grant-Storage-Access-to-App -ctx $ctx -IllumioAppId $appPrincipal.Id
        }

        # providing network and firewall access if requested
        if ($nsg) {
            $err = Grant-Network-Access-to-App -ctx $ctx -IllumioAppId $appPrincipal.Id
            if ($err) {
                throw $err
            }
            $err = Grant-Firewall-Access-to-App -ctx $ctx -IllumioAppId $appPrincipal.Id
            if ($err) {
                throw $err
            }
        }
        elseif ($azfw) {
            $err = Grant-Firewall-Access-to-App -ctx $ctx -IllumioAppId $appPrincipal.Id
            if ($err) {
                throw $err
            }
        }
        Write-Host "Sending Azure AD application credentials to cloudsecure`n"
        # creating payload for callback to Cloudsecure
        $encodedSecret = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$secretText"))
        $payLoad = @{
            "type"            = "AzureRole";
            "client_id"       = $appId;
            "client_secret"   = $encodedSecret
            "azure_tenant_id" = $tenantId;
        }

        if ($subscriptionId -ne "") {
            $payLoad["subscription_id"] = $subscriptionId
        }
        $err = Send-API-Request -payLoad $payLoad -endPoint $CredentialsEndpoint
        if ($err) {
            throw $err
        }

        #         Write-Host -ForegroundColor DarkYellow @"
        # Name                            Value
        # ----                            ----
        # "@
        #         Write-Host @"
        # Client ID                       $appId`n
        # Tenant ID                       $( $ctx.Tenant.Id )`n
        # Subscription ID                 $subscriptionId`n
        # Client Secret                   $( $appSecret.SecretText )`n
        # "@
        if (-not $DryRun) {
            Write-Host "All Onboarding steps for Illumio CloudSecure in Azure are successfully completed`n." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error creating Azure Ad Application and assigning permissions: $_"
        Send-AccountEvent -message "Creating AD application and assigning permissions failed" -details "$_"

        if ($r) {
            Write-Host "Removing role '$( $r.Name )'`n"
            Remove-AzRoleDefinition -Id $r.Id -Force
        }

        if ($illumioApp -and -not $existingAppId -and -not $DryRun) {
            Write-Host "Removing app '$AppName'`n"
            Remove-AzADApplication -InputObject $illumioApp
        }
        return $_
    }
}

function Grant-Storage-Access-to-App {
    param (
        $ctx,
        $IllumioAppId
    )

    try {
        # Getting the storage scope for the given storage accounts
        $storageScopes = get-StorageScopes -storageAccounts $storageAccounts -ctx $ctx
        if ($storageAccounts -and !$storageScopes) {
            throw "Storage Accounts $storageAccounts are invalid. Please provide valid storage account names `n"
        }

        # If storage accounts were given, providing the accesss to it.
        $destination = @()
        if ($storageScopes) {
            Write-Host "Assign storage roles for scopes $storageScopes for Azure AD App client $IllumioAppId`n"
            foreach ($sp in $storageScopes) {
                # for the given storage accounts adding the storage blob data reader role.
                $err = Add-Role-To-Scope -scope $sp -role $StorageReaderRole -objId $IllumioAppId
                if ($err) {
                    Write-Host "Error Assigning $($StorageReaderRole) on scope $sp. Continuing to other storage accounts`n" -ForegroundColor Red
                }
                else {
                    # a role that was already assigned counts as granted too
                    $destination += $sp
                }
            }
        }

        # making api callback to Cloudsecure
        $destination = Select-Object -InputObject $destination -Unique
        Write-Host "Granted Access to Azure AD app for destinations $destination`n"
        $payLoad = @{
            "subscription_id" = $subscriptionId;
            "type"            = "AzureFlow";
            "destinations"    = $destination;
        }

        $err = Send-API-Request -payLoad $payLoad -endPoint $CredentialsEndpoint
        if ($err) {
            throw $err
        }

    }
    catch {
        Write-Host "Error: $_"
    }
}

function Send-AccountEvent {
    param (
        $message,
        $details,
        $errorCode = $DefaultErrorCode
    )
    # nothing was attempted in a dry run, so there is no failure to report
    if ($DryRun) {
        return
    }
    try {
        $accountEvent = @{
            "category"   = "ONBOARDING";
            "status"     = "FAILED";
            "message"    = $message;
            "details"    = $details;
            "producer"   = "powershell";
            "error_code" = $errorCode;
        }
        $accountId = ""
        if ($subscriptionId -ne "") {
            $accountId = $subscriptionId
        }
        elseif ($tenantId -ne "") {
            $accountId = $tenantId
        }
        $payLoad = @{
            "cloud"         = "azure";
            "account_id"    = $accountId;
            "account_event" = $accountEvent;
        }

        $endPoint = $EventsEndpoint -replace "{account_id}", $accountId
        $err = Send-API-Request -payLoad $payLoad -endPoint $endPoint
        if ($err) {
            Write-Host "Error sending account event: $err" -ForegroundColor Red
            return $err
        }
        Write-Host "Account event sent successfully for account $accountId" -ForegroundColor Green
    }
    catch {
        Write-Host "Error in Send-AccountEvent: $_" -ForegroundColor Red
        return $_
    }
}

function Send-API-Request {
    param (
        $payLoad,
        $endPoint
    )
    $contentType = "application/json; charset=utf-8"
    $method = "Post"

    $headers = Get-ApiHeaders -serviceAccountKey $serviceAccountKey -serviceAccountToken $serviceAccountToken -csTenantId $csTenantId -contentType $contentType
    $uri = Get-ApiUri -baseUrl $url -endPoint $endPoint

    try {
        # converting payload to json
        $jsonPayload = ConvertTo-Json $payLoad
        Write-Host "API call to $uri`n"
        # setting tls version to 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $response = Invoke-Change -description "Send '$($payLoad.type)' data to CloudSecure ($uri)" -dryRunResult @{ StatusCode = 0 } -action {
            Invoke-WebRequest -Uri $uri -Headers $headers -Method $method -Body $jsonPayload -ErrorAction Stop
        }
        if ($($response.StatusCode -eq 200)) {
            Write-Host "API call to Cloudsecure Successful" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Api call Failed with error:" -ForegroundColor Red
        Write-Host $_.Exception.Message
        return $_.Exception.Message
    }
}

# Utility function to get API headers
function Get-ApiHeaders {
    param (
        $serviceAccountKey,
        $serviceAccountToken,
        $csTenantId,
        $contentType
    )
    # encoding serviceAccountKey and serviceAccountToken using base64 encoding.
    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($serviceAccountKey):$($serviceAccountToken)"))

    # setting up the required header
    $headers = @{
        "Content-Type"  = $contentType;
        "Authorization" = "Basic $basicAuth";
        "X-Tenant-Id"   = $csTenantId;
    }
    return $headers
}

# Utility function to construct API URI
function Get-ApiUri {
    param (
        $baseUrl,
        $endPoint
    )
    $uri = $baseUrl
    # handle for dev testing
    if ($baseUrl -like "*dev.cloud*") {
        $uri = "https://cs-dev-proxy.console.ilabs.io"

    }
    elseif ($baseUrl -like "*qa.cloud*") {
        $uri = "https://cs-qa-proxy.console.ilabs.io"
    }
    elseif ($baseUrl -like "*stage.cloud*") {
        $uri = "https://cs-stage-proxy.stage.cloud.ilabs.io"
    }
    elseif ($baseUrl -like "*cloud.sunnyvale.*") {
        $uri = "https://cs-dev-proxy-onboarding.sunnyvale.ilabs.io"
    }
    $uri = $uri + $endPoint

    return $uri
}

function Grant-Firewall-Access-to-App {
    param (
        $ctx,
        $IllumioAppId
    )

    try {
        if ($azfw -or $nsg) {

            Write-Host "Registering Microsoft.Network for Firewall read/write access`n"
            Invoke-Change -description "Register resource provider Microsoft.Network" -action {
                Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-Null
            }
            $subsRoleName = ""
            if ($sid -ne "") {
                $subsRoleName = "$RoleName-$subscriptionId"
            }
            elseif ($tid -ne "") {
                $subsRoleName = "$RoleName-$tenantId"
            }
            else {
                throw "subscription or tenant id cannot be empty"
            }

            Write-Host "Checking if $subsRoleName exists in scope $scope `n"
            $role = Get-AzRoleDefinition -Name $subsRoleName -Scope $scope
            if (-Not $role) {
                # Role does not exist, hence creating a new role.
                # Create a new Role for Illumio Firewall Administration
                Write-Host "Creating role '$subsRoleName'`n"
                Invoke-Change -description "Create custom role '$subsRoleName' on scope $scope ($($FirewallRoleActions.Count) actions)" -action {
                    $newRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
                    $newRole.Name = $subsRoleName
                    $newRole.Description = "Illumio Firewall Administrator role"
                    $newRole.IsCustom = $true
                    $newRole.Actions = $FirewallRoleActions
                    $newRole.AssignableScopes = $scope

                    New-AzRoleDefinition -Role $newRole | Out-null
                    for ($i = 0; $i -le 30; $i++) {
                        $r = Get-AzRoleDefinition -Name $subsRoleName -WarningAction Ignore
                        if ($r) {
                            break
                        }
                        Start-Sleep -Seconds 2
                    }
                }
            }
            else {
                Write-Host "$subsRoleName Already exists on the scope $scope.`n"
            }

            #Assign the created role
            $err = Add-Role-To-Scope -scope $scope -role $subsRoleName -objId $IllumioAppId
            if ($err) {
                throw $err
            }
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor "Red"
        return $_
    }

}

function New-Application-Secret {
    param(
        $illumioAppId
    )

    try {
        $startDate = Get-Date
        $endDate = $startDate.AddDays($secretExpirationDays)

        Write-Host "Creating app Credentials (Expiry set to $endDate)`n"
        $bytes = [System.Text.Encoding]::Unicode.GetBytes("illumio")
        $credDesc = [System.Convert]::ToBase64String($bytes)
        $appSecret = Invoke-Change -description "Create client secret for app $illumioAppId (expires $endDate)" -dryRunResult @{ SecretText = "<new-client-secret>" } -action {
            New-AzADAppCredential -ApplicationId $illumioAppId -StartDate $startDate -EndDate $endDate -CustomKeyIdentifier $credDesc
        }
        return $appSecret

    }
    catch {
        Write-Host "Error Occured: $_" -ForegroundColor "Red"
    }
}

function Reset-Application-Secret {
    param(
        $illumioAppId
    )
    try {
        Write-Host "Rotating the secret for Ad Application`n"
        $appSecret = New-Application-Secret($illumioAppId)
        if ( -not $appSecret) {
            throw "error generating secret for app"
        }
        $encodedSecret = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($appSecret.SecretText)"))
        $payLoad = @{
            "type"            = "AzureRole";
            "client_id"       = $illumioAppId;
            "client_secret"   = $encodedSecret
            "azure_tenant_id" = $tenantId;
        }

        if ($subscriptionId -ne "") {
            $payLoad["subscription_id"] = $subscriptionId
        }
        $err = Send-API-Request -payLoad $payLoad -endPoint $CredentialsEndpoint
        if ($err) {
            throw $err
        }


    }
    catch {
        Write-Host "Error: $_" -ForegroundColor "Red"
        return $_
    }
}

function Grant-Network-Access-to-App {
    param (
        $ctx,
        $IllumioAppId
    )

    try {
        if ($nsg) {

            Write-Host "Registering Microsoft.Network for network access`n"
            Invoke-Change -description "Register resource provider Microsoft.Network" -action {
                Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-null
            }

            $subsRoleName = ""
            if ($nsgRoleId -or $nsgRoleName) {
                # assign a role that already exists instead of creating the Illumio role
                if ($nsgRoleId) {
                    $role = Get-AzRoleDefinition -Id $nsgRoleId
                }
                else {
                    $role = Get-AzRoleDefinition -Name $nsgRoleName
                }
                if (-not $role) {
                    throw "NSG role '$nsgRoleId$nsgRoleName' was not found. Check -nsgRoleId / -nsgRoleName"
                }
                $subsRoleName = $role.Name
                Write-Host "Using existing NSG role: $subsRoleName`n"
            }
            else {
                if ($sid -ne "") {
                    $subsRoleName = "$IllumioNSGRoleName-$subscriptionId"
                }
                elseif ($tid -ne "") {
                    $subsRoleName = "$IllumioNSGRoleName-$tenantId"
                }
                else {
                    throw "subscription or tenant id cannot be empty"
                }

                Write-Host "Checking if $subsRoleName exists in scope $scope`n"
                $role = Get-AzRoleDefinition -Name $subsRoleName -Scope $scope

                if (-Not $role) {
                    # Role does not exists, hence creating a new role.
                    # Create a new role for Illumio Azure Network Security Administrator
                    Write-Host "Role $subsRolename does not exist. Creating new"
                    Invoke-Change -description "Create custom role '$subsRoleName' on scope $scope ($($NSGRoleActions.Count) actions)" -action {
                        $newRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
                        $newRole.Name = $subsRoleName
                        $newRole.Description = "Illumio Network Administration Role"
                        $newRole.IsCustom = $true
                        $newRole.Actions = $NSGRoleActions
                        $newRole.AssignableScopes = $scope

                        New-AzRoleDefinition -Role $newRole | Out-null
                        Write-Host "Role creation successful '$( $newRole.Name )'`n"
                        for ($i = 0; $i -le 30; $i++) {
                            $r = Get-AzRoleDefinition -Name $subsRoleName -WarningAction Ignore
                            if ($r) {
                                break
                            }
                            Start-Sleep -Seconds 2
                        }
                    }
                }
                else {
                    Write-Host "$subsRoleName Already exists on the scope $scope.`n"

                    # check if role has all required permissions, update if it does not have all the required permissions
                    $missing = @()
                    foreach ($requiredAction in $NSGRoleActions) {
                        if ($role.Actions -notcontains $requiredAction) {
                            $missing += $requiredAction
                        }
                    }

                    if ($missing.Count -gt 0) {
                        Write-Host "Role $subsRoleName is missing permissions. Adding missing actions: $missing"
                        Invoke-Change -description "Add $($missing.Count) missing action(s) to role '$subsRoleName': $missing" -action {
                            $role.Actions = @($role.Actions + $missing | Select-Object -Unique)
                            Set-AzRoleDefinition -Role $role | Out-Null
                            Write-Host "Updated role $subsRoleName with missing permissions." -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "Role $subsRoleName already has all required permissions." -ForegroundColor Green
                    }
                }
            }

            # Assign the Created Role
            $err = Add-Role-To-Scope -scope $scope -role $subsRoleName -objId $IllumioAppId
            if ($err) {
                throw $err
            }
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor "Red"
        return $_
    }
}

function Get-DataplaneMetadata {
    param (
        $dataplaneMetadataPath
    )

    try {
        if (-not $dataplaneMetadataPath -or -not (Test-Path -Path $dataplaneMetadataPath -PathType Leaf)) {
            throw "dataplaneMetadataPath is empty or does not exist: $dataplaneMetadataPath"
        }

        Write-Host "Loading dataplane metadata from file $dataplaneMetadataPath"
        $jsonContent = Get-Content -Path $dataplaneMetadataPath -Raw
        $metadata = ConvertFrom-Json $jsonContent

        if (-not $metadata) {
            throw "Failed to parse dataplane metadata JSON from $dataplaneMetadataPath"
        }

        if (-not (($metadata.PSObject.Properties.Name -contains 'ipGroups') -and ($metadata.PSObject.Properties.Name -contains 'regions'))) {
            throw "Invalid dataplane metadata schema: expected 'ipGroups' and 'regions' keys."
        }
        return $metadata
    }
    catch {
        Write-Host "Error reading dataplane metadata: $_" -ForegroundColor Red
        return $null
    }
}

# Utility function to download dataplane metadata from a URL into a temporary file
function Download-DataplaneMetadata {
    try {
        if (-not $DataplaneMetadataUrl) {
            throw "dataplane metadata URL is empty"
        }

        Write-Host "Downloading dataplane metadata from URL $DataplaneMetadataUrl"
        $tempDir = [System.IO.Path]::GetTempPath()
        $tempFile = [System.IO.Path]::Combine($tempDir, "dataplane-ips.json")

        Invoke-WebRequest -Uri $DataplaneMetadataUrl -OutFile $tempFile -ErrorAction Stop

        if (-not (Test-Path -Path $tempFile -PathType Leaf)) {
            throw "Failed to download dataplane metadata to temporary file: $tempFile"
        }

        return $tempFile
    }
    catch {
        Write-Host "Error downloading dataplane metadata: $_" -ForegroundColor Red
        return $null
    }
}

# Function to update storage account firewall settings based on region matching
function Update-StorageAccountFirewallWithRegions {
    param (
        $ctx,
        $storageAccounts,
        $dataplaneMetadata
    )

    if (-not $storageAccounts) {
        Write-Host "No storage accounts provided for firewall update. Skipping..." -ForegroundColor Yellow
        return $null
    }

    Write-Host "Updating firewall settings for storage accounts based on region matching." -ForegroundColor Green

    try {
        $updatedAccounts = @()
        $storageAccounts = $storageAccounts.split(',')
        # remove duplicates
        $storageAccounts = $storageAccounts | Select-Object -Unique
        foreach ($storageAccount in $storageAccounts) {
            # resourceId:= /subscriptions/7cc25562-a9a4-42a5-813c-56b5b7a9f3dc/resourceGroups/illumioresourcegroup_eastus/providers/Microsoft.Storage/storageAccounts/illumiosa0b5a09eastus
            $saName = $storageAccount -split "/"
            $saName = $saName[-1]
            $resourceGroupName = $storageAccount -split "/"
            $resourceGroupName = $resourceGroupName[4]

            Write-Host "Processing storage account: $saName in resource group: $resourceGroupName" -ForegroundColor Cyan

            # Get storage account details to fetch its location
            $sa = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $saName -DefaultProfile $ctx -ErrorAction Stop
            if ($sa) {
                $saRegion = $sa.Location
                Write-Host "Storage account $saName is in region: $saRegion" -ForegroundColor Cyan

                $ips = $null
                $dataplaneRegion = $dataplaneMetadata.regions.$saRegion

                if ($dataplaneRegion -and ($dataplaneRegion -ne $saRegion)) {
                    $groupData = $dataplaneMetadata.ipGroups.$dataplaneRegion
                    if ($groupData -and $groupData.ips) {
                        $ips = $groupData.ips
                    }
                    else {
                        Write-Host "IP group 'dataplaneRegion' not found or has no IPs." -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "Region $saRegion not mapped to any IP group." -ForegroundColor Yellow
                }

                if ($ips -and $ips.Count -gt 0) {
                    Write-Host "Applying IPs: $ips" -ForegroundColor Green
                    $networkRuleSet = $sa.NetworkRuleSet
                    if (-not $networkRuleSet) {
                        $networkRuleSet = @{Bypass = 'AzureServices'; DefaultAction = 'Deny'; IPRules = @(); VirtualNetworkRules = @() }
                    }

                    $existingIPs = $networkRuleSet.IPRules | ForEach-Object { $_.IPAddressOrRange }
                    $uniqueIPs = $ips | Where-Object { $_ -notin $existingIPs }
                    if ($uniqueIPs.Count -gt 0) {
                        Write-Host "Applying unique IPs: $uniqueIPs" -ForegroundColor Green
                        foreach ($ip in $uniqueIPs) {
                            $ipRule = @{IPAddressOrRange = $ip; Action = 'Allow' }
                            $networkRuleSet.IPRules += $ipRule
                        }

                        Invoke-Change -description "Allow $(@($uniqueIPs).Count) Illumio IP(s) on the firewall of storage account ${saName}: $uniqueIPs" -action {
                            Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $resourceGroupName -Name $saName -Bypass $networkRuleSet.Bypass -DefaultAction $networkRuleSet.DefaultAction -IPRule $networkRuleSet.IPRules -VirtualNetworkRule $networkRuleSet.VirtualNetworkRules -DefaultProfile $ctx -ErrorAction Stop | Out-Null
                            Write-Host "Updated firewall settings for storage account: $saName with IPs: $uniqueIPs" -ForegroundColor Green
                        }
                        $updatedAccounts += $storageAccount
                    }
                    else {
                        Write-Host "No new unique IPs to apply for storage account: $saName" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "Storage account $saName not found in resource group $resourceGroupName" -ForegroundColor Red
            }
        }

        return $null
    }
    catch {
        Write-Host "Error updating storage account firewall settings: $_" -ForegroundColor Red
        return $_
    }
}

# Replaces the __NAME__ placeholders of a script template
function Expand-Template {
    param (
        [string]$template,
        [hashtable]$values
    )
    foreach ($key in $values.Keys) {
        $template = $template.Replace("__$($key)__", [string]$values[$key])
    }
    return $template
}

# Builds a script that does the onboarding with the Azure CLI (az) or with Az PowerShell (ps), for customers who
# review and run the commands themselves. Nothing is read from or changed in Azure, so no login is needed.
# Secrets never end up in the script: it reads them from environment variables when it runs.
function New-SetupScript {
    param (
        $target
    )

    if ($remove -or $whitelistStorageAccounts) {
        throw "-Generate does not support -remove and -whitelistStorageAccounts. Use -DryRun to preview these"
    }
    if ($sid -eq "" -and $tid -eq "") {
        throw "subscription id or tenant id cannot be empty"
    }
    foreach ($value in @($sid, $tid, $clientId, $existingAppId, $nsgRoleId, $nsgRoleName, $name, $csTenantId, $url)) {
        if ($value -match '["`$\\]') {
            throw "'$value' contains a character that cannot be used in a generated script"
        }
    }
    $accounts = @($storageAccounts | Where-Object { $_ } | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($account in $accounts) {
        if ($account -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]+$') {
            throw "Storage account '$account' is not a resource ID (/subscriptions/<id>/resourceGroups/<group>/providers/Microsoft.Storage/storageAccounts/<name>)"
        }
    }

    # the same decisions as in the live run: a rotation does nothing else, and -nsg includes the firewall role
    $rotate = $clientId -ne "" -and $rotateSecret
    $newApp = $clientId -eq "" -and $existingAppId -eq ""
    $sendCredentials = $clientId -eq "" -or $rotate
    $secretFromEnv = $clientId -eq "" -and $existingAppId -ne ""
    $registerFeatures = $clientId -eq "" -and $azfw
    $grantStorage = -not $rotate -and $accounts.Count -gt 0
    $grantNsg = -not $rotate -and $nsg
    $grantFirewall = -not $rotate -and ($nsg -or $azfw)
    $customNsgRole = $grantNsg -and -not $nsgRoleId -and -not $nsgRoleName
    $usesApi = $sendCredentials -or $grantStorage
    $suffix = if ($sid -ne "") { $sid } else { $tid }
    $existingApp = if ($clientId -ne "") { $clientId } else { $existingAppId }

    # environment variables the generated script needs: name, description
    $envVars = [System.Collections.ArrayList]@()
    if ($usesApi) {
        [Void]$envVars.Add(@("ILLUMIO_KEY", "CloudSecure service account key"))
        [Void]$envVars.Add(@("ILLUMIO_TOKEN", "CloudSecure service account token"))
        if ($csTenantId -eq "") {
            [Void]$envVars.Add(@("ILLUMIO_TENANT_ID", "CloudSecure tenant ID"))
        }
        if ($url -eq "") {
            [Void]$envVars.Add(@("ILLUMIO_API", "CloudSecure URL"))
        }
    }
    if ($secretFromEnv) {
        [Void]$envVars.Add(@("ILLUMIO_APP_SECRET", "client secret of app $existingAppId"))
    }

    $values = @{
        TARGET        = if ($sid -ne "") { "subscription $sid" } else { "tenant $tid" }
        DATE          = Get-Date -Format "yyyy-MM-dd"
        REQUIRED_ROLE = if ($customNsgRole -or $grantFirewall) { "Owner" } else { "Owner or User Access Administrator" }
        SID           = $sid
        TID           = $tid
        APP_NAME      = if ($name -ne "") { $name } else { $DefaultAppName }
        APP_ID        = $existingApp
        DAYS          = [int][Math]::Ceiling($secretExpirationDays)
        CS_TENANT     = $csTenantId
        API           = if ($url -ne "") { Get-ApiUri -baseUrl $url.TrimEnd('/') -endPoint "" } else { "" }
        ENDPOINT      = $CredentialsEndpoint
        READER        = $ReaderRole
        STORAGE_ROLE  = $StorageReaderRole
        NSG_ROLE      = "$IllumioNSGRoleName-$suffix"
        NSG_ROLE_REF  = "$nsgRoleId$nsgRoleName"
        FW_ROLE       = "$RoleName-$suffix"
        NSG_ACTIONS   = ($NSGRoleActions | ForEach-Object { "    `"$_`"" }) -join ",`n"
        FW_ACTIONS    = ($FirewallRoleActions | ForEach-Object { "    `"$_`"" }) -join ",`n"
        DESTINATIONS  = ConvertTo-Json -InputObject $accounts -Compress
        ENV_NAMES     = ($envVars | ForEach-Object { $_[0] }) -join " "
        ENV_NAMES_PS  = ($envVars | ForEach-Object { "`"$($_[0])`"" }) -join ", "
    }

    $parts = @()
    if ($target -eq "az") {
        $values["ENV_HELP"] = ($envVars | ForEach-Object { "#       export $($_[0])=<$($_[1])>" }) -join "`n"
        $values["STORAGE_LINES"] = ($accounts | ForEach-Object { "  `"$_`"" }) -join "`n"
        $values["SUB_FIELD"] = if ($sid -ne "") { ',"subscription_id":"%s"' } else { "" }
        $values["SUB_ARG"] = if ($sid -ne "") { ' "$SUBSCRIPTION_ID"' } else { "" }

        $parts += @'
#!/usr/bin/env bash
# Illumio CloudSecure onboarding for Azure __TARGET__
# Generated by illumio-init.ps1 -Generate az on __DATE__. Review it before you run it.
#
# Requirements:
#   - Azure CLI, signed in (az login) as __REQUIRED_ROLE__ on the __TARGET__
'@
        if ($usesApi) {
            $parts += '#   - curl and base64'
        }
        if ($envVars.Count -gt 0) {
            $parts += @'
#   - these environment variables (secrets are deliberately not stored in this file):
__ENV_HELP__
'@
        }
        $parts += @'
# The script can be run again: existing roles and role assignments are kept.
set -euo pipefail

'@
        if ($usesApi) {
            $parts += @'
ILLUMIO_TENANT_ID="${ILLUMIO_TENANT_ID:-__CS_TENANT__}"
ILLUMIO_API="${ILLUMIO_API:-__API__}"
'@
        }
        if ($envVars.Count -gt 0) {
            $parts += @'
for VARIABLE in __ENV_NAMES__; do
  if [ -z "${!VARIABLE:-}" ]; then
    echo "Set $VARIABLE first, see the requirements at the top of this script" >&2
    exit 1
  fi
done

'@
        }
        # only the variables that the rest of the script uses
        if ($sid -ne "") {
            $parts += @'
SUBSCRIPTION_ID="__SID__"
az account set --subscription "$SUBSCRIPTION_ID"
'@
            if ($sendCredentials) {
                $parts += 'TENANT_ID=$(az account show --query tenantId -o tsv)'
            }
            if (-not $rotate) {
                $parts += 'SCOPE="/subscriptions/$SUBSCRIPTION_ID"'
            }
        }
        else {
            $parts += @'
TENANT_ID="__TID__"
if [ "$(az account show --query tenantId -o tsv)" != "$TENANT_ID" ]; then
  echo "Sign in to the tenant first: az login --tenant $TENANT_ID" >&2
  exit 1
fi
'@
            if (-not $rotate) {
                $parts += 'SCOPE="/providers/Microsoft.Management/managementGroups/$TENANT_ID"'
            }
        }
        if ($usesApi) {
            $parts += @'

# sends a JSON document to the CloudSecure API
cloudsecure_post() {
  curl --fail --silent --show-error --request POST "$ILLUMIO_API$1" \
    --user "$ILLUMIO_KEY:$ILLUMIO_TOKEN" \
    --header "X-Tenant-Id: $ILLUMIO_TENANT_ID" \
    --header "Content-Type: application/json; charset=utf-8" \
    --data "$2" >/dev/null
}
'@
        }
        if ($customNsgRole -or $grantFirewall) {
            $parts += @'

# creates a custom role; an existing role is kept, or reset to this definition if $3 is "update"
ensure_role() {
  local name="$1" definition="$2"
  if [ -z "$(az role definition list --name "$name" --scope "$SCOPE" --query "[0].name" -o tsv)" ]; then
    echo "Creating role '$name'"
    az role definition create --role-definition "$definition" --output none
    # a new role takes a moment before it can be assigned
    for _ in $(seq 1 30); do
      [ -n "$(az role definition list --name "$name" --scope "$SCOPE" --query "[0].name" -o tsv)" ] && break
      sleep 2
    done
  elif [ "${3:-}" = "update" ]; then
    echo "Updating role '$name'"
    az role definition update --role-definition "$definition" --output none
  else
    echo "Role '$name' already exists"
  fi
}
'@
        }
        if ($registerFeatures) {
            $parts += @'

# Azure Firewall logging features
az feature register --namespace Microsoft.Network --name AFWEnableNetworkRuleNameLogging --output none
az feature register --namespace Microsoft.Network --name AFWEnableStructuredLogs --output none
'@
        }
        if ($registerFeatures -or $grantNsg -or $grantFirewall) {
            $parts += @'

# Resource provider for network and firewall management
az provider register --namespace Microsoft.Network
'@
        }
        if ($newApp) {
            $parts += @'

# App registration, client secret (valid __DAYS__ days) and service principal
APP_ID=$(az ad app create --display-name "__APP_NAME__" --query appId -o tsv)
END_DATE=$(date -u -d "+__DAYS__ days" +%Y-%m-%d 2>/dev/null || date -u -v+__DAYS__d +%Y-%m-%d)
APP_SECRET=$(az ad app credential reset --id "$APP_ID" --append --display-name illumio --end-date "$END_DATE" --query password -o tsv)
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || az ad sp create --id "$APP_ID" --query id -o tsv)
'@
        }
        elseif ($rotate) {
            $parts += @'

# New client secret (valid __DAYS__ days) for the existing app registration
APP_ID="__APP_ID__"
END_DATE=$(date -u -d "+__DAYS__ days" +%Y-%m-%d 2>/dev/null || date -u -v+__DAYS__d +%Y-%m-%d)
APP_SECRET=$(az ad app credential reset --id "$APP_ID" --append --display-name illumio --end-date "$END_DATE" --query password -o tsv)
'@
        }
        else {
            $parts += @'

# Existing app registration
APP_ID="__APP_ID__"
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)
'@
            if ($secretFromEnv) {
                $parts += 'APP_SECRET="$ILLUMIO_APP_SECRET"'
            }
        }
        if ($clientId -eq "") {
            $parts += @'

# Read access to the __TARGET__
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "__READER__" --scope "$SCOPE" --output none
'@
        }
        if ($grantStorage) {
            $parts += @'

# Read access to the flow log storage accounts
STORAGE_ACCOUNTS=(
__STORAGE_LINES__
)
for STORAGE_ACCOUNT in "${STORAGE_ACCOUNTS[@]}"; do
  az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
    --role "__STORAGE_ROLE__" --scope "$STORAGE_ACCOUNT" --output none
done
cloudsecure_post "__ENDPOINT__" '{"subscription_id":"__SID__","type":"AzureFlow","destinations":__DESTINATIONS__}'
'@
        }
        if ($customNsgRole) {
            $parts += @'

# Custom role for network security group management
NSG_ROLE="__NSG_ROLE__"
NSG_ROLE_DEFINITION=$(cat <<EOF
{
  "Name": "$NSG_ROLE",
  "Description": "Illumio Network Administration Role",
  "Actions": [
__NSG_ACTIONS__
  ],
  "AssignableScopes": ["$SCOPE"]
}
EOF
)
ensure_role "$NSG_ROLE" "$NSG_ROLE_DEFINITION" update
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "$NSG_ROLE" --scope "$SCOPE" --output none
'@
        }
        elseif ($grantNsg) {
            $parts += @'

# Existing role for network security group management
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "__NSG_ROLE_REF__" --scope "$SCOPE" --output none
'@
        }
        if ($grantFirewall) {
            $parts += @'

# Custom role for Azure Firewall management
FW_ROLE="__FW_ROLE__"
FW_ROLE_DEFINITION=$(cat <<EOF
{
  "Name": "$FW_ROLE",
  "Description": "Illumio Firewall Administrator role",
  "Actions": [
__FW_ACTIONS__
  ],
  "AssignableScopes": ["$SCOPE"]
}
EOF
)
ensure_role "$FW_ROLE" "$FW_ROLE_DEFINITION"
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "$FW_ROLE" --scope "$SCOPE" --output none
'@
        }
        if ($sendCredentials) {
            $parts += @'

# Hand the app credentials to CloudSecure
APP_SECRET_B64=$(printf '%s' "$APP_SECRET" | base64 | tr -d '\n')
cloudsecure_post "__ENDPOINT__" "$(printf '{"type":"AzureRole","client_id":"%s","client_secret":"%s","azure_tenant_id":"%s"__SUB_FIELD__}' \
  "$APP_ID" "$APP_SECRET_B64" "$TENANT_ID"__SUB_ARG__)"
'@
        }
        $parts += @'

echo "All steps for Illumio CloudSecure are completed"
'@
    }
    else {
        $values["ENV_HELP"] = ($envVars | ForEach-Object { "#       `$env:$($_[0]) = `"<$($_[1])>`"" }) -join "`n"
        $values["STORAGE_LINES"] = ($accounts | ForEach-Object { "    `"$_`"" }) -join ",`n"

        $parts += @'
# Illumio CloudSecure onboarding for Azure __TARGET__
# Generated by illumio-init.ps1 -Generate ps on __DATE__. Review it before you run it.
#
# Requirements:
#   - PowerShell 7.4 or higher with the Az module, signed in (Connect-AzAccount) as __REQUIRED_ROLE__ on the __TARGET__
'@
        if ($envVars.Count -gt 0) {
            $parts += @'
#   - these environment variables (secrets are deliberately not stored in this file):
__ENV_HELP__
'@
        }
        $parts += @'
# The script can be run again: existing roles and role assignments are kept.
$ErrorActionPreference = "Stop"

'@
        if ($usesApi) {
            $parts += @'
if (-not $env:ILLUMIO_TENANT_ID) { $env:ILLUMIO_TENANT_ID = "__CS_TENANT__" }
if (-not $env:ILLUMIO_API) { $env:ILLUMIO_API = "__API__" }
'@
        }
        if ($envVars.Count -gt 0) {
            $parts += @'
foreach ($variable in __ENV_NAMES_PS__) {
    if (-not [Environment]::GetEnvironmentVariable($variable)) {
        throw "Set `$env:$variable first, see the requirements at the top of this script"
    }
}

'@
        }
        if ($sid -ne "") {
            $parts += @'
$subscriptionId = "__SID__"
$scope = "/subscriptions/$subscriptionId"
Select-AzSubscription -SubscriptionId $subscriptionId | Out-Null
$tenantId = (Get-AzContext).Tenant.Id
'@
        }
        else {
            $parts += @'
$tenantId = "__TID__"
$scope = "/providers/Microsoft.Management/managementGroups/$tenantId"
Set-AzContext -TenantId $tenantId | Out-Null
'@
        }
        if ($usesApi) {
            $parts += @'

# sends a document to the CloudSecure API
function Send-CloudSecure {
    param ($endPoint, $payLoad)
    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($env:ILLUMIO_KEY):$($env:ILLUMIO_TOKEN)"))
    $headers = @{
        "Content-Type"  = "application/json; charset=utf-8"
        "Authorization" = "Basic $basicAuth"
        "X-Tenant-Id"   = $env:ILLUMIO_TENANT_ID
    }
    Invoke-WebRequest -Uri "$($env:ILLUMIO_API)$endPoint" -Headers $headers -Method Post -Body (ConvertTo-Json $payLoad) | Out-Null
}
'@
        }
        if (-not $rotate) {
            $parts += @'

# assigns a role to the app, unless the app already holds it on the scope
function Add-Role {
    param ($role, $roleScope)
    try {
        $roleDef = Get-AzRoleDefinition -Name $role -WarningAction Ignore
        New-AzRoleAssignment -ObjectId $spId -RoleDefinitionId $roleDef.Id -Scope $roleScope | Out-Null
    }
    catch {
        if (-not $_.Exception.Message.Contains("Conflict")) {
            throw
        }
        Write-Host "Role $role is already assigned on scope $roleScope"
    }
}
'@
        }
        if ($customNsgRole -or $grantFirewall) {
            $parts += @'

# creates a custom role; an existing role is kept, with -update it gets the actions it is missing
function Set-CustomRole {
    param ($name, $description, $actions, [switch]$update)
    $role = Get-AzRoleDefinition -Name $name -Scope $scope -WarningAction Ignore
    if (-not $role) {
        Write-Host "Creating role '$name'"
        $newRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
        $newRole.Name = $name
        $newRole.Description = $description
        $newRole.IsCustom = $true
        $newRole.Actions = $actions
        $newRole.AssignableScopes = $scope
        New-AzRoleDefinition -Role $newRole | Out-Null
        # a new role takes a moment before it can be assigned
        for ($i = 0; $i -le 30; $i++) {
            if (Get-AzRoleDefinition -Name $name -WarningAction Ignore) {
                break
            }
            Start-Sleep -Seconds 2
        }
    }
    elseif ($update) {
        $missing = @($actions | Where-Object { $role.Actions -notcontains $_ })
        if ($missing.Count -gt 0) {
            Write-Host "Adding missing actions to role '$name': $missing"
            $role.Actions = @($role.Actions + $missing | Select-Object -Unique)
            Set-AzRoleDefinition -Role $role | Out-Null
        }
    }
}
'@
        }
        if ($registerFeatures) {
            $parts += @'

# Azure Firewall logging features
foreach ($feature in "AFWEnableNetworkRuleNameLogging", "AFWEnableStructuredLogs") {
    Register-AzProviderFeature -FeatureName $feature -ProviderNamespace "Microsoft.Network" | Out-Null
}
'@
        }
        if ($registerFeatures -or $grantNsg -or $grantFirewall) {
            $parts += @'

# Resource provider for network and firewall management
Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-Null
'@
        }
        if ($newApp) {
            $parts += @'

# App registration, client secret (valid __DAYS__ days) and service principal
$appId = (New-AzADApplication -DisplayName "__APP_NAME__").AppId
$secretName = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("illumio"))
$appSecret = (New-AzADAppCredential -ApplicationId $appId -StartDate (Get-Date) -EndDate (Get-Date).AddDays(__DAYS__) -CustomKeyIdentifier $secretName).SecretText
$spId = (New-AzADServicePrincipal -ApplicationId $appId -Description "Illumio App Service Principal").Id
'@
        }
        elseif ($rotate) {
            $parts += @'

# New client secret (valid __DAYS__ days) for the existing app registration
$appId = "__APP_ID__"
$secretName = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("illumio"))
$appSecret = (New-AzADAppCredential -ApplicationId $appId -StartDate (Get-Date) -EndDate (Get-Date).AddDays(__DAYS__) -CustomKeyIdentifier $secretName).SecretText
'@
        }
        else {
            $parts += @'

# Existing app registration
$appId = "__APP_ID__"
$spId = (Get-AzADServicePrincipal -ApplicationId $appId).Id
if (-not $spId) {
    throw "Unable to find the service principal of app $appId"
}
'@
            if ($secretFromEnv) {
                $parts += '$appSecret = $env:ILLUMIO_APP_SECRET'
            }
        }
        if ($clientId -eq "") {
            $parts += @'

# Read access to the __TARGET__
Add-Role -role "__READER__" -roleScope $scope
'@
        }
        if ($grantStorage) {
            $parts += @'

# Read access to the flow log storage accounts
$storageAccounts = @(
__STORAGE_LINES__
)
foreach ($storageAccount in $storageAccounts) {
    Add-Role -role "__STORAGE_ROLE__" -roleScope $storageAccount
}
Send-CloudSecure -endPoint "__ENDPOINT__" -payLoad @{
    "subscription_id" = "__SID__"
    "type"            = "AzureFlow"
    "destinations"    = $storageAccounts
}
'@
        }
        if ($customNsgRole) {
            $parts += @'

# Custom role for network security group management
$nsgRole = "__NSG_ROLE__"
Set-CustomRole -name $nsgRole -description "Illumio Network Administration Role" -update -actions @(
__NSG_ACTIONS__
)
Add-Role -role $nsgRole -roleScope $scope
'@
        }
        elseif ($grantNsg) {
            $parts += @'

# Existing role for network security group management
'@
            if ($nsgRoleId) {
                $parts += '$nsgRole = (Get-AzRoleDefinition -Id "__NSG_ROLE_REF__").Name'
            }
            else {
                $parts += '$nsgRole = "__NSG_ROLE_REF__"'
            }
            $parts += 'Add-Role -role $nsgRole -roleScope $scope'
        }
        if ($grantFirewall) {
            $parts += @'

# Custom role for Azure Firewall management
$firewallRole = "__FW_ROLE__"
Set-CustomRole -name $firewallRole -description "Illumio Firewall Administrator role" -actions @(
__FW_ACTIONS__
)
Add-Role -role $firewallRole -roleScope $scope
'@
        }
        if ($sendCredentials) {
            $parts += @'

# Hand the app credentials to CloudSecure
$payLoad = @{
    "type"            = "AzureRole"
    "client_id"       = $appId
    "client_secret"   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($appSecret))
    "azure_tenant_id" = $tenantId
}
'@
            if ($sid -ne "") {
                $parts += '$payLoad["subscription_id"] = $subscriptionId'
            }
            $parts += 'Send-CloudSecure -endPoint "__ENDPOINT__" -payLoad $payLoad'
        }
        $parts += @'

Write-Host "All steps for Illumio CloudSecure are completed" -ForegroundColor Green
'@
    }

    # the script file may have Windows line endings, a bash script must not
    return (Expand-Template -template ($parts -join "`n") -values $values).Replace("`r`n", "`n") + "`n"
}

# main
# -Generate is passed: write the commands as a script instead of running them
if ($Generate) {
    try {
        if ($DryRun) {
            throw "Use either -DryRun or -Generate"
        }
        $setupScript = New-SetupScript -target $Generate
        if ($OutFile -ne "") {
            $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
            [System.IO.File]::WriteAllText($path, $setupScript)
            Write-Host "Wrote $path. Review it before you run it." -ForegroundColor Green
        }
        else {
            $setupScript
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    }
    return
}

try {
    # check for powershell version 7.4 or higher
    if ($PSVersionTable.PSVersion.Major -lt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
        throw "PowerShell version 7.4 or higher is required. Current version is $($PSVersionTable.PSVersion)."
    }
    else {
        Write-Host "PowerShell version 7.4 or higher is installed." -ForegroundColor Green
    }

    # check for Az module
    if (-not (Get-InstalledModule -Name Az -ErrorAction SilentlyContinue)) {
        Write-Host "Az module is not installed." -ForegroundColor Red
        $response = Read-Host "Do you want to install the Az module now? (Y/N)"
        if ($response -match '^[Yy]') {
            Write-Host "Installing Az module (this may take a few minutes)..."
            Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force
            if (Get-InstalledModule -Name Az -ErrorAction SilentlyContinue) {
                Import-Module Az -ErrorAction SilentlyContinue
                Write-Host "Az module installation successful." -ForegroundColor Green
            }
            else {
                throw "Error installing Az module. Installation completed but Az module not found."
            }
        }
        else {
            Write-Host "Az module installation declined. Exiting script." -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "Az module is installed." -ForegroundColor Green
    }
}
catch {
    Write-Host "Error: $_." -ForegroundColor Red
    Send-AccountEvent -message "Environment preflight failed" -details "$_"
    exit 1
}

$ctx = Get-AzContext
if (!$ctx) {
    Connect-AzAccount -UseDeviceAuthentication
}

# setting application name
if ($name -ne "") {
    $AppName = $name
}
else {
    $AppName = $DefaultAppName
}

try {
    $orgSubscId = $ctx.Subscription.Id
    $orgTenantId = $ctx.Tenant.Id
    
    # a dry run sends nothing to CloudSecure, so it works without the CloudSecure credentials
    if (-not $DryRun) {
        if ($serviceAccountKey -eq "" -or $serviceAccountToken -eq "") {
            throw "ServiceAccountKey and ServiceAccountToken cannot be empty"
        }
        if ($csTenantId -eq "") {
            throw "Cloudsecure Tenant Id cannot be empty"
        }
        if ($url -eq "") {
            throw "url cannot be empty"
        }
    }

    if ($subscriptionId -ne "") {
        # subscription Onboarding
        $scope = "$SubscriptionScopePrefix/$subscriptionId"
        $tenantId = $orgTenantId

        Write-Host "Select subscription $subscriptionId`n"
        Select-AzSubscription -SubscriptionId $subscriptionId -TenantId $orgTenantId | Out-Null
    }
    elseif ($tenantId -ne "") {
        # tenant Onboarding
        $scope = "$TenantScopePrefix/$tenantId"

        Write-Host "Select Tenant $tenantId`n"
        Set-AzContext -TenantId $tenantId | Out-Null

    }
    else {
        throw "subscription id or tenant id cannot be empty"
    }

    # check user permission before proceeding (needs the target subscription / tenant selected)
    $err = Confirm-User-Permission-For-Scope -scope $scope
    if ($err) {
        throw $err
    }
}
catch {
    Write-Host "Error: $_"
    if ($orgSubscId) {
        Select-AzSubscription -SubscriptionId $orgSubscId -TenantId $orgTenantId -ErrorAction SilentlyContinue | Out-Null
    }
    Send-AccountEvent -message "Input validation or scope selection failed" -details "$_"
    exit 1
}

$ctx = Get-AzContext

try {
    if ($sid -ne "") {
        Write-Host "Using subscription $( $ctx.Subscription.Id ), tenant $( $ctx.Tenant.Id )`n"
    }
    else {
        Write-Host "Using Tenant $( $ctx.Tenant.Id )`n"
    }
    # -remove is passed
    if ($remove) {
        remove-Illumio-App -ctx $ctx
        return
    }

    # -whitelistStorageAccounts is passed
    if ($whitelistStorageAccounts) {
        if ($storageAccounts) {
            $path = Download-DataplaneMetadata -dataplaneMetadataUrl $dataplaneMetadataUrl
            if (-not $path) {
                Write-Host "Failed to download dataplane metadata from URL $dataplaneMetadataUrl. Skipping firewall update." -ForegroundColor Yellow
                return
            }
            $dataplaneMetadata = Get-DataplaneMetadata -dataplaneMetadataPath $path
            if ($dataplaneMetadata) {
                Write-Host "Using dataplane metadata to apply IPs based on region matching." -ForegroundColor Green
                $err = Update-StorageAccountFirewallWithRegions -ctx $ctx -storageAccounts $storageAccounts -dataplaneMetadata $dataplaneMetadata
                if ($err) {
                    throw $err
                }
            }
            else {
                Write-Host "Dataplane metadata file not available or invalid. Skipping firewall update." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "No storage accounts provided for whitelisting. Skipping..." -ForegroundColor Yellow
        }
        return
    }

    # - clientId passed. No Need to create the application again
    if ($clientId -eq "") {
        $err = install-Illumio-App -ctx $ctx -existingAppId $existingAppId -existingAppSecret $existingAppSecret
        if ($err) {
            throw $err
        }
    }
    elseif ($clientId -and $rotateSecret ) {
        $err = Reset-Application-Secret($clientId)
        if ($err) {
            throw $err
        }
    }
    else {
        Write-Host "Using Existing Application with client id $clientId`n"
        Write-Host "Creating Azure Active Directory App principal`n"
        $appPrincipal = Get-AzADServicePrincipal -ApplicationId $clientId
        if (!$appPrincipal) {
            throw "Error Getting ADServicePrincipal. Check if the Client Id Exists"
        }

        # Adding storage account access for existing application
        if ($clientId -and $storageAccounts) {
            Grant-Storage-Access-to-App -ctx $ctx -IllumioAppId $appPrincipal.Id
        }

        # Adding network permissions if app already exists
        if ($clientId -and $nsg) {
            $err = Grant-Network-Access-to-App -ctx $ctx -IllumioAppId  $appPrincipal.Id
            if ($err) {
                throw $err
            }
            $err = Grant-Firewall-Access-to-App -ctx $ctx -IllumioAppId  $appPrincipal.Id
            if ($err) {
                throw $err
            }
        }

        # Adding firewall permissions if app already exists
        if ($clientId -and $azfw) {
            Grant-Firewall-Access-to-App -ctx $ctx -IllumioAppId  $appPrincipal.Id
        }
    }
}
catch {
    Write-Host "Error: $_"
}
finally {
    if ($DryRun) {
        Write-Host "`nDry run finished. Nothing was changed. $($plannedChanges.Count) change(s) would be made:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $plannedChanges.Count; $i++) {
            Write-Host "  $($i + 1). $($plannedChanges[$i])" -ForegroundColor Cyan
        }
        Write-Host ""
    }
    if ($orgSubscId) {
        Write-Host "Select subscription $orgSubscId, tenant $orgTenantId`n"
        Select-AzSubscription -SubscriptionId $orgSubscId -TenantId $orgTenantId | Out-null
    }
}