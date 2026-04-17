param($sid = "", $tid = "", $clientId = "", $name = "",
    [Single][validateRange(1, 1000)]$secretExpirationDays = 365,
    $serviceAccountKey = "", $serviceAccountToken = "", $csTenantId = "", $url = "",
    [String[]]$storageAccounts, [switch]$azfw, [switch]$remove, [switch]$nsg, [switch]$rotateSecret,
    [switch]$whitelistStorageAccounts, $dataplaneMetadataPath = "",
    $existingAppId = "", $existingAppSecret = "")

# Input from user
$subscriptionId = $sid
$tenantId = $tid

# Global variables.
$scope = ""
$AppName = ""

$ErrorActionPreference = "Stop"

New-Variable -Name DefaultAppName -Value "Illumio-CloudSecure-Access" -Option Constant
New-Variable -Name RoleName -Value "Illumio Firewall Administrator" -Option Constant
New-Variable -Name NSGRoleName -Value "Illumio Network Security Administrator" -Option Constant
New-Variable -Name SubscriptionScopePrefix -Value "/subscriptions" -Option Constant
New-Variable -Name TenantScopePrefix -Value "/providers/Microsoft.Management/managementGroups" -Option Constant
New-Variable -Name ReaderRole -Value "Reader" -Option Constant
New-Variable -Name StorageReaderRole -Value "Storage Blob Data Reader" -Option Constant
New-Variable -Name DataplaneMetadataUrl -Value "https://cloudsecure-integration-templates.s3.us-west-2.amazonaws.com/dataplane-ips-dev.json" -Option Constant
New-Variable -Name CredentialsEndpoint -Value "/api/v1/integrations/cloud_credentials" -Option Constant
New-Variable -Name EventsEndpoint -Value "/api/v1/integrations/cloud/azure/accounts/{account_id}/event" -Option Constant
New-Variable -Name DefaultErrorCode -Value "APP_REGISTRATION_FAILED" -Option Constant


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
            $illumioApp = New-AzADApplication -DisplayName $AppName

            $appId = $illumioApp.AppId

            $appSecret = New-Application-Secret($appId)
            if (-not $appSecret) {
                throw "error generating secret"
            }
            $secretText = $appSecret.SecretText

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
        Write-Host "All Onboarding steps for Illumio CloudSecure in Azure are successfully completed`n." -ForegroundColor Green
    }
    catch {
        Write-Host "Error creating Azure Ad Application and assigning permissions: $_"
        Send-AccountEvent -message "Creating AD application and assigning permissions failed" -details "$_"

        if ($r) {
            Write-Host "Removing role '$( $r.Name )'`n"
            Remove-AzRoleDefinition -Id $r.Id -Force
        }

        if ($illumioApp -and -not $existingAppId) {
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

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method $method -Body $jsonPayload -ErrorAction Stop
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
        $appSecret = New-AzADAppCredential -ApplicationId $illumioAppId -StartDate $startDate -EndDate $endDate -CustomKeyIdentifier $credDesc
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
            Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-null
            
            $subsRoleName = ""
            if ($sid -ne "") {
                $subsRoleName = "$NSGRoleName-$subscriptionId"
            }
            elseif ($tid -ne "") {
                $subsRoleName = "$NSGRoleName-$tenantId"
            }
            else {
                throw "subscription or tenant id cannot be empty"
            }

            Write-Host "Checking if $subsRoleName exists in scope $scope`n"
            $role = Get-AzRoleDefinition -Name $subsRoleName -Scope $scope
            $actions = @(
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
            
            if (-Not $role) {
                # Role does not exists, hence creating a new role.
                # Create a new role for Illumio Azure Network Security Administrator
                Write-Host "Role $subsRolename does not exist. Creating new"
                
                $newRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
                $newRole.Name = $subsRoleName
                $newRole.Description = "Illumio Network Administration Role"
                $newRole.IsCustom = $true
                $newRole.Actions = $actions
                $newRole.AssignableScopes = $scope

                Write-Host "Creating role '$( $newRole.Name )'`n"
                New-AzRoleDefinition -Role $newRole | Out-null
                Write-Host "Role creation successful '$( $newRole.Name )'`n"
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
                
                # check if role has all required permissions, update if it does not have all the required permissions
                $missing = @()
                foreach ($action in $actions) {
                    if ($role.Actions -notcontains $action) {
                        $missing += $action
                    }
                }
                
                if ($missing.Count -gt 0) {
                    Write-Host "Role $subsRoleName is missing permissions. Adding missing actions: $missing"
                    $role.Actions = @($role.Actions + $missing | Select-Object -Unique)
                    Set-AzRoleDefinition -Role $role | Out-Null
                    Write-Host "Updated role $subsRoleName with missing permissions." -ForegroundColor Green
                }
                else {
                    Write-Host "Role $subsRoleName already has all required permissions." -ForegroundColor Green
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

                        Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $resourceGroupName -Name $saName -Bypass $networkRuleSet.Bypass -DefaultAction $networkRuleSet.DefaultAction -IPRule $networkRuleSet.IPRules -VirtualNetworkRule $networkRuleSet.VirtualNetworkRules -DefaultProfile $ctx -ErrorAction Stop | Out-Null
                        Write-Host "Updated firewall settings for storage account: $saName with IPs: $uniqueIPs" -ForegroundColor Green
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

# main
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
    
    if ($serviceAccountKey -eq "" -or $serviceAccountToken -eq "") {
        throw "ServiceAccountKey and ServiceAccountToken cannot be empty"
    }
    if ($csTenantId -eq "") {
        throw "Cloudsecure Tenant Id cannot be empty"
    }
    if ($url -eq "") {
        throw "url cannot be empty"
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
    if ($orgSubscId) {
        Write-Host "Select subscription $orgSubscId, tenant $orgTenantId`n"
        Select-AzSubscription -SubscriptionId $orgSubscId -TenantId $orgTenantId | Out-null
    }
}