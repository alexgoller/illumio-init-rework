param(
    $sid = "", 
    $tid = "", 
    $clientId = "", 
    $name = "", 
    [Single][validateRange(1, 1000)]$secretExpirationDays = 365,
    $serviceAccountKey = "", 
    $serviceAccountToken = "", 
    $csTenantId = "", 
    $url = "",
    [String[]]$storageAccounts, 
    [switch]$azfw, 
    [switch]$remove, 
    [switch]$nsg,
    $existingAppId = "",  # New parameter for existing AppId
    $existingAppSecret = "",  # New parameter for existing App Secret
    $nsgRoleId = "",  # New parameter for custom NSG role ID
    $nsgRoleName = ""  # New parameter for custom NSG role name
)

# Input from user
$subscriptionId = $sid
$tenantId = $tid

# Global variables.
$scope = ""
$AppName = ""

$ErrorActionPreference = "Stop"

New-Variable -Name DefaultAppName -Value "Illumio-CloudSecure-Access" -Option Constant
New-Variable -Name RoleName -Value "Illumio Firewall Administrator" -Option Constant
New-Variable -Name DefaultNSGRoleName -Value "Network Security Group Contributor" -Option Constant
New-Variable -Name SubscriptionScopePrefix -Value "/subscriptions" -Option Constant
New-Variable -Name TenantScopePrefix -Value "/providers/Microsoft.Management/managementGroups" -Option Constant
New-Variable -Name ReaderRole -Value "Reader" -Option Constant
New-Variable -Name StorageReaderRole -Value "Storage Blob Data Reader" -Option Constant


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
                        Remove-AzRoleAssignment -InputObject $assignment | Out-Null
                    }
                }
                $subsRoleName = "$RoleName-$( $c.Subscription.Id )"
                foreach ($assignment in Get-AzRoleAssignment -RoleDefinitionName $subsRoleName -DefaultProfile $c) {
                    Write-Host "Removing role assignment $( $assignment.RoleAssignmentId )`n"
                    try {
                        Remove-AzRoleAssignment -InputObject $assignment -DefaultProfile $c  | Out-Null
                    }
                    catch {
                    }
                }

                $r = Get-AzRoleDefinition -Name $subsRoleName -DefaultProfile $c -WarningAction Ignore
                if ($r) {
                    Write-Host "Removing role '$subsRoleName'`n"
                    try {
                        Remove-AzRoleDefinition -InputObject $r -DefaultProfile $c -Force -WarningAction Ignore | Out-Null
                    }
                    catch {
                    }
                }
            }
        }

        foreach ($app in Get-AzADApplication -DisplayName $AppName) {
            Write-Host "Removing app '$( $app.Id )'`n"
            Remove-AzADApplication -ApplicationId $app.AppId
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
        $roles = Get-AzRoleAssignment -ObjectId $user.Id -Scope $scope
        $hasPermission = $false
        Write-Host "Checking if user has Owner or User Access Administrator Role on scope $scope`n"
        foreach ($r in $roles) {
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

function Add-Role-To-Scope {
    param (
        $scope,
        $role,
        $objId
    )

    try {
        #fetching role definition id
        $roleDef = Get-AzRoleDefinition -Name $role

        Write-Host "Assigning role $role to the app principal $objId on scope $scope"
        New-AzRoleAssignment -ObjectId $objId -RoleDefinitionId $roleDef.Id -Scope $scope | Out-Null
    }
    catch {
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
                Register-AzProviderFeature -FeatureName $feature -ProviderNamespace "Microsoft.Network" | Out-null
            }

            Write-Host "Registering Microsoft.Network`n"
            Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-null
        }

        if ($existingAppId -and $existingAppSecret) {
            Write-Host "Using existing Azure Active Directory App Registration`n"
            $appId = $existingAppId
            $appSecret = $existingAppSecret
            $appPrincipal = Get-AzADServicePrincipal -ApplicationId $appId
            if (!$appPrincipal) {
                throw "Error: Unable to find Service Principal for the provided AppId"
            }
        } else {
            # Create AD App
            Write-Host "Creating Azure Active Directory App Registration`n"
            $illumioApp = New-AzADApplication -DisplayName $AppName

            $appId = $illumioApp.AppId

            $startDate = Get-Date
            $endDate = $startDate.AddDays($secretExpirationDays)

            Write-Host "Creating app credentials (Expiry set to $endDate)`n"
            $bytes = [System.Text.Encoding]::Unicode.GetBytes("illumio")
            $credDesc = [Convert]::ToBase64String($bytes)
            $appSecretObj = New-AzADAppCredential -ApplicationId $appId -StartDate $startDate -EndDate $endDate -CustomKeyIdentifier $credDesc
            $appSecret = $appSecretObj.SecretText

            Write-Host "Creating Azure Active Directory App Principal`n"
            $appPrincipal = New-AzADServicePrincipal -ApplicationId $appId -Description "Illumio App Service Principal"
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
        Write-Host "Sending Azure AD application credentials to cloudsecure`n"
        # creating payload for callback to Cloudsecure
        $encodedSecret = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$appSecret"))
        $payLoad = @{
            "type"            = "AzureRole";
            "client_id"       = $appId;
            "client_secret"   = $encodedSecret
            "azure_tenant_id" = $tenantId;
        }

        if ($subscriptionId -ne "") {
            $payLoad["subscription_id"] = $subscriptionId
        }
        $err = Send-API-Request -payLoad $payLoad
        if ($err) {
            throw $err
        }

        Write-Host "All Onboarding steps for Illumio CloudSecure in Azure are successfully completed`n." -ForegroundColor Green
    }
    catch {
        Write-Host "Error creating or using Azure Ad Application and assigning permissions: $_"

        if ($r) {
            Write-Host "Removing role '$( $r.Name )'`n"
            Remove-AzRoleDefinition -Id $r.Id -Force
        }

        if ($illumioApp -and !$existingAppId) {
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
                try {
                    Write-Host "Assigning role $($StorageReaderRole) to $sp`n"
                    New-AzRoleAssignment -ObjectId $IllumioAppId -RoleDefinitionName $StorageReaderRole -Scope $sp -ErrorAction:Stop | Out-null
                    $destination += $sp
                }
                catch {
                    if ($_.Exception.Message.Contains("Conflict")) {
                        Write-Host "Client has $($StorageReaderRole) on scope $sp. So skipping and continuing to other storage accounts`n" -ForegroundColor Yellow
                        # adding the storage scope to granted destinations as conflict implies the permission is already granted.
                        $destination += $sp
                    }
                    else {
                        Write-Host "Error Assigning $($StorageReaderRole) on scope $scope. $_`n" -ForegroundColor Red
                    }
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

        $err = Send-API-Request -payLoad $payLoad
        if ($err) {
            throw $err
        }

    }
    catch {
        Write-Host "Error: $_"
    }
}

function Send-API-Request {
    param (
        $payLoad
    )
    $contentType = "application/json; charset=utf-8"
    $method = "Post"
    $endPoint = "/api/v1/integrations/cloud_credentials"

    # encoding serviceAccountKey and serviceAccountToken using base64 encoding.
    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($serviceAccountKey):$($serviceAccountToken)"))

    # setting up the required header
    $headers = @{
        "Content-Type"  = $contentType;
        "Authorization" = "Basic $basicAuth";
        "X-Tenant-Id"   = $csTenantId;
    }
    $uri = $url
    # handle for dev testing
    if ($url -like "*dev.cloud*") {
        $uri = "https://cs-dev-proxy.console.ilabs.io/"
    }
    elseif ($url -like "*qa.cloud*") {
        $uri = "https://cs-qa-proxy.console.ilabs.io/"
    }

    if (-not($uri -like "*proxy*")) {
        $uri = $uri + $endPoint
    }

    try {
        # converting payload to json
        $jsonPayload = ConvertTo-Json $payLoad
        Write-Host "API call to $uri`n"
        # setting tls version to 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method $Method -Body $jsonPayload -ErrorAction Stop
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

function Grant-Firewall-Access-to-App {
    param (
        $ctx,
        $IllumioAppId
    )

    try {
        if ($azfw -or $nsg) {

            Write-Host "Registering Microsoft.Network for Firewall read/write access`n"
            Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-Null
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
                $actions = "Microsoft.Network/azurefirewalls/read",
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

                $newRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
                $newRole.Name = $subsRoleName
                $newRole.Description = "Illumio Firewall Administrator role"
                $newRole.IsCustom = $true
                $newRole.Actions = $actions
                $newRole.AssignableScopes = $scope

                Write-Host "Creating role '$( $newRole.Name )'`n"
                New-AzRoleDefinition -Role $newRole | Out-null
                for ($i = 0; $i -le 30; $i++) {
                    $r = Get-AzRoleDefinition -Name $subsRoleName -WarningAction Ignore | Out-null
                    if ($r) {
                        break
                    }
                    Start-Sleep -Seconds 2
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
        Write-Host "Error: $_"
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
            Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-null
            
            $roleToAssign = $DefaultNSGRoleName
            
            if ($nsgRoleId) {
                $role = Get-AzRoleDefinition -Id $nsgRoleId
                if ($role) {
                    $roleToAssign = $role.Name
                    Write-Host "Using custom NSG role: $($role.Name) (ID: $nsgRoleId)`n"
                } else {
                    Write-Host "Warning: Provided NSG role ID not found. Using default role.`n" -ForegroundColor Yellow
                }
            } elseif ($nsgRoleName) {
                $role = Get-AzRoleDefinition -Name $nsgRoleName
                if ($role) {
                    $roleToAssign = $nsgRoleName
                    Write-Host "Using custom NSG role: $nsgRoleName`n"
                } else {
                    Write-Host "Warning: Provided NSG role name not found. Using default role.`n" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Using default NSG role: $DefaultNSGRoleName`n"
            }

            Write-Host "Assigning $roleToAssign role to the app`n"
            $err = Add-Role-To-Scope -scope $scope -role $roleToAssign -objId $IllumioAppId
            if ($err) {
                throw $err
            }
        }
    }
    catch {
        Write-Host "Error: $_"
        return $_
    }
}

# main
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
    
    if ($serviceAccountKey -eq "" -or $serviceAccountToken -eq "") {
        throw "ServiceAccountKey and ServiceAccountToken cannot be empty"
    }
    if ($csTenantId -eq "") {
        throw "Cloudsecure Tenant Id cannot be empty"
    }
    if ($url -eq "") {
        throw "url cannot be emtpy"
    }

    if ($subscriptionId -ne "") {
        # subscription Onboarding
        $scope = "$SubscriptionScopePrefix/$subscriptionId"
        $tenantId = $orgTenantId
        # check user permission before proceeding
        $err = Confirm-User-Permission-For-Scope -scope $scope
        if ($err) {
            throw $err
        }

        Write-Host "Select subscription $subscriptionId`n"
        Select-AzSubscription -SubscriptionId $subscriptionId -TenantId $orgTenantId | Out-Null
    }
    elseif ($tenantId -ne "") {
        # tenant Onboarding
        $scope = "$TenantScopePrefix/$tenantId"

        # check user permission before proceeding
        $err = Confirm-User-Permission-For-Scope -scope $scope
        if ($err) {
            throw $err
        }

        Write-Host "Select Tenant $tenantId`n"
        Set-AzContext -TenantId $tenantId | Out-Null

    }
    else {
        throw "subscription id or tenant id cannot be empty"
    }
}
catch {
    Write-Host "Error: $_"
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
    # - clientId passed. No Need to create the application again
    if ($clientId -eq "") {
        $err = install-Illumio-App -ctx $ctx -existingAppId $existingAppId -existingAppSecret $existingAppSecret
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
    if ($orgSubscId) {
        Write-Host "Select subscription $orgSubscId, tenant $orgTenantId`n"
        Select-AzSubscription -SubscriptionId $orgSubscId -TenantId $orgTenantId | Out-null
    }
}
