# Tests for illumio-init.ps1. No Azure access needed: the Az cmdlets are mocked (mocks.ps1) and the generated
# bash script runs against fake az and curl commands.
#   pwsh tests/run-tests.ps1
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$work = Join-Path ([System.IO.Path]::GetTempPath()) "illumio-init-tests-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $work | Out-Null
$fails = 0

function Check {
    param($name, $condition, $detail = "")
    if ($condition) {
        Write-Host "PASS  $name"
    }
    else {
        Write-Host "FAIL  $name $detail" -ForegroundColor Red
        $script:fails++
    }
}

# Runs a script in a new PowerShell with mocked Az cmdlets. Returns its output, exit code and the changes it made.
function Invoke-Script {
    param($arguments, $state = @{}, $script = "illumio-init.ps1")
    $env:MOCK_LOG = Join-Path $work "calls-$([guid]::NewGuid()).log"
    $env:MOCK_STATE = ConvertTo-Json $state -Depth 5 -Compress
    $path = if ([System.IO.Path]::IsPathRooted($script)) { $script } else { "$repo/$script" }
    $out = & pwsh -NoProfile -Command ". '$PSScriptRoot/mocks.ps1'; & '$path' $arguments" 2>&1 | Out-String
    # @( ) around the if: a one-line log would otherwise collapse to a string
    $log = @(if (Test-Path $env:MOCK_LOG) { Get-Content $env:MOCK_LOG })
    return [pscustomobject]@{ Out = $out; Code = $LASTEXITCODE; Log = $log }
}

$sub = "/subscriptions/sub-1"
$sa = "$sub/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/illumiosa1"
$cs = "-serviceAccountKey KEY1 -serviceAccountToken TOKEN1 -csTenantId cs-tenant -url https://cloud.example.com"
$nsgRole = "Illumio Network Security Administrator-sub-1"
$fwRole = "Illumio Firewall Administrator-sub-1"

# --- both scripts parse ---
foreach ($f in "illumio-init.ps1", "illumio-init-extended.ps1") {
    $errs = $null
    [System.Management.Automation.Language.Parser]::ParseFile("$repo/$f", [ref]$null, [ref]$errs) | Out-Null
    Check "$f parses" ($errs.Count -eq 0)
}

# --- normal run (mocked): behaviour is unchanged by the dry-run layer ---
$r = Invoke-Script "-sid sub-1 $cs -nsg -storageAccounts $sa"
Check "run: creates app, secret and principal" (($r.Log -join "|") -like "New-AzADApplication Illumio-CloudSecure-Access|New-AzADAppCredential app-1|New-AzADServicePrincipal app-1|*")
Check "run: assigns Reader" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-Reader $sub")
Check "run: assigns storage role" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-Storage Blob Data Reader $sa")
Check "run: creates and assigns NSG role" ($r.Log -contains "New-AzRoleDefinition $nsgRole" -and $r.Log -contains "New-AzRoleAssignment sp-1 id-of-$nsgRole $sub")
Check "run: creates and assigns firewall role" ($r.Log -contains "New-AzRoleDefinition $fwRole" -and $r.Log -contains "New-AzRoleAssignment sp-1 id-of-$fwRole $sub")
Check "run: sends storage destinations" (@($r.Log -like "Invoke-WebRequest https://cloud.example.com/api/v1/integrations/cloud_credentials cs-tenant *illumiosa1*AzureFlow*").Count -eq 1)
$secret = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("s3cr3t"))
Check "run: sends app credentials" (@($r.Log -like "Invoke-WebRequest *AzureRole*").Count -eq 1 -and ($r.Log -join "|") -like "*`"client_secret`":`"$secret`"*")
Check "run: reports success, no dry-run output" ($r.Out -like "*successfully completed*" -and $r.Out -notlike "*dry-run*")

$r = Invoke-Script "-sid sub-1 $cs -azfw"
Check "run -azfw: assigns firewall role for a new app" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-$fwRole $sub")
Check "run -azfw: does not create NSG role" ($r.Log -notcontains "New-AzRoleDefinition $nsgRole")

$r = Invoke-Script "-sid sub-1 $cs -existingAppId app-9 -existingAppSecret APPSECRET" @{ assignments = @(@{ role = "Reader"; objId = "sp-1"; scope = "/providers/Microsoft.Management/managementGroups/mg1" }) }
Check "run existing app: no app created, inherited Reader not assigned again" (@($r.Log -like "New-Az*").Count -eq 0)
Check "run existing app: credentials sent" (@($r.Log -like "Invoke-WebRequest *`"client_id`":`"app-9`"*AzureRole*").Count -eq 1)

$r = Invoke-Script "-sid sub-1 $cs -existingAppId app-9 -existingAppSecret APPSECRET" @{ assignments = @(@{ role = "Reader"; objId = "sp-1"; scope = "$sub/resourceGroups/rg1" }) }
Check "run existing app: Reader on a resource group only is not enough" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-Reader $sub")

$r = Invoke-Script "-sid sub-1 $cs -nsg" @{ roles = @{ $nsgRole = @("Microsoft.Network/networkSecurityGroups/read") } }
Check "run: existing NSG role gets missing actions" (@($r.Log -like "Set-AzRoleDefinition $nsgRole 23").Count -eq 1 -and $r.Log -notcontains "New-AzRoleDefinition $nsgRole")

# --- existing NSG role (-nsgRoleName / -nsgRoleId), formerly illumio-init-extended.ps1 ---
$r = Invoke-Script "-sid sub-1 $cs -nsg -nsgRoleName 'My NSG Role'" @{ roles = @{ "My NSG Role" = @() } }
Check "nsgRoleName: assigns the given role, creates no NSG role" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-My NSG Role $sub" -and $r.Log -notcontains "New-AzRoleDefinition $nsgRole")
$r = Invoke-Script "-sid sub-1 $cs -nsg -nsgRoleId 'id-of-My NSG Role'" @{ roles = @{ "My NSG Role" = @() } }
Check "nsgRoleId: assigns the given role" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-My NSG Role $sub")
$r = Invoke-Script "-sid sub-1 $cs -nsg -nsgRoleName 'Missing Role'"
Check "nsgRoleName: unknown role is an error and the new app is removed" ($r.Out -like "*was not found*" -and $r.Log -contains "Remove-AzADApplication app-1")

$r = Invoke-Script "-sid sub-1 $cs -nsg" @{ roles = @{ "Network Security Group Contributor" = @() } } "illumio-init-extended.ps1"
Check "extended wrapper: forwards and keeps its default NSG role" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-Network Security Group Contributor $sub" -and $r.Log -notcontains "New-AzRoleDefinition $nsgRole")
$r = Invoke-Script "-sid sub-1 $cs -nsg -nsgRoleName 'My NSG Role'" @{ roles = @{ "My NSG Role" = @() } } "illumio-init-extended.ps1"
Check "extended wrapper: forwards -nsgRoleName" ($r.Log -contains "New-AzRoleAssignment sp-1 id-of-My NSG Role $sub")

# --- dry run ---
$r = Invoke-Script "-sid sub-1 -DryRun -nsg -azfw -storageAccounts $sa"
Check "dry run: changes nothing, needs no CloudSecure credentials" ($r.Log.Count -eq 0 -and $r.Code -eq 0)
foreach ($expected in "Register feature Microsoft.Network/AFWEnableStructuredLogs", "Create app registration 'Illumio-CloudSecure-Access'",
    "Create client secret", "Create service principal", "Assign role 'Reader' to the app principal <new-service-principal-id> on scope $sub",
    "Assign role 'Storage Blob Data Reader'", "Create custom role '$nsgRole'", "Assign role '$nsgRole'", "Create custom role '$fwRole'",
    "Assign role '$fwRole'", "Send 'AzureFlow' data to CloudSecure", "Send 'AzureRole' data to CloudSecure") {
    Check "dry run: reports '$expected'" ($r.Out -like "*``[dry-run``] would: $expected*")
}
Check "dry run: prints a summary and no success message" ($r.Out -like "*Nothing was changed. 1* change(s) would be made*" -and $r.Out -notlike "*successfully completed*")

$r = Invoke-Script "-sid sub-1 -DryRun -clientId app-9 -nsg" @{ roles = @{ $nsgRole = @("Microsoft.Network/networkSecurityGroups/read"); $fwRole = @() }; assignments = @(@{ role = $fwRole; objId = "sp-1"; scope = $sub }) }
Check "dry run: reflects existing state" ($r.Log.Count -eq 0 -and $r.Out -like "*would: Add 22 missing action(s) to role '$nsgRole'*" -and $r.Out -notlike "*would: Create custom role*" -and $r.Out -notlike "*would: Assign role '$fwRole'*" -and $r.Out -like "*would: Assign role '$nsgRole'*")

$r = Invoke-Script "-sid sub-1 -DryRun -remove" @{ assignments = @(@{ role = $fwRole; objId = "sp-1"; scope = $sub }) }
Check "dry run -remove: removes nothing" ($r.Log.Count -eq 0 -and $r.Out -like "*would: Remove app registration 'Illumio-CloudSecure-Access' (app-1)*" -and $r.Out -like "*would: Remove role assignment*")

$r = Invoke-Script "-sid sub-1 -DryRun -whitelistStorageAccounts -storageAccounts $sa"
Check "dry run -whitelistStorageAccounts: changes no firewall" ($r.Log.Count -eq 0 -and $r.Out -like "*would: Allow 2 Illumio IP(s) on the firewall of storage account illumiosa1: 192.0.2.10 192.0.2.11*")
$r = Invoke-Script "-sid sub-1 $cs -whitelistStorageAccounts -storageAccounts $sa"
Check "run -whitelistStorageAccounts: updates the firewall" (@($r.Log -like "Update-AzStorageAccountNetworkRuleSet illumiosa1 192.0.2.10 192.0.2.11").Count -eq 1)

# --- permission check (group-delegated roles) ---
$SubscriptionScopePrefix = "/subscriptions"
$TenantScopePrefix = "/providers/Microsoft.Management/managementGroups"
$tenant = "$TenantScopePrefix/tenant-1"
function Get-AzRoleAssignment {
    [CmdletBinding()]
    # the same parameters as the real ObjectIdParameterSet: passing -Scope here fails
    param([Parameter(Mandatory)]$ObjectId, $RoleDefinitionName, [switch]$ExpandPrincipalGroups)
    if (-not $ExpandPrincipalGroups) { throw "ExpandPrincipalGroups not passed" }
    $script:assignments
}
function Get-AzAdUser { [pscustomobject]@{ Id = "user-1"; DisplayName = "Test User" } }
function A($scope, $role) { [pscustomobject]@{ Scope = $scope; RoleDefinitionName = $role } }
$ast = [System.Management.Automation.Language.Parser]::ParseFile("$repo/illumio-init.ps1", [ref]$null, [ref]$null)
$ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq "Confirm-User-Permission-For-Scope" }, $true) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
function Allowed($scope) {
    try { $e = Confirm-User-Permission-For-Scope -scope $scope 6>$null 2>$null; return $null -eq $e } catch { return $false }
}
$assignments = @(A $sub "Owner"); Check "permission: Owner via group on subscription" (Allowed $sub)
$assignments = @(A $sub "User Access Administrator"); Check "permission: User Access Administrator via group" (Allowed $sub)
$assignments = @(A "$TenantScopePrefix/some-mg" "Owner"); Check "permission: Owner inherited from management group" (Allowed $sub)
$assignments = @(A "/" "Owner"); Check "permission: Owner inherited from root" (Allowed $sub)
$assignments = @(A "$sub/resourceGroups/rg1" "Owner"); Check "permission: Owner on resource group only is rejected" (-not (Allowed $sub))
$assignments = @(A $sub "Contributor"); Check "permission: Contributor is rejected" (-not (Allowed $sub))
$assignments = @(A $tenant "Owner"); Check "permission: tenant, Owner on root management group" (Allowed $tenant)
$assignments = @(A "$TenantScopePrefix/child-mg" "Owner"); Check "permission: tenant, Owner on child management group rejected" (-not (Allowed $tenant))

# --- generated scripts ---
function New-Generated {
    param($arguments)
    $r = Invoke-Script $arguments
    return [pscustomobject]@{ Text = $r.Out; Code = $r.Code; Log = $r.Log }
}

$full = "-sid sub-1 $cs -nsg -azfw -storageAccounts $sa -existingAppSecret APPSECRET"
foreach ($target in "az", "ps") {
    $g = New-Generated "$full -Generate $target"
    Check "generate ${target}: needs no Azure and changes nothing" ($g.Code -eq 0 -and $g.Log.Count -eq 0)
    Check "generate ${target}: contains no secrets" ($g.Text -cnotlike "*KEY1*" -and $g.Text -cnotlike "*TOKEN1*" -and $g.Text -cnotlike "*APPSECRET*")
    Check "generate ${target}: contains every role action" ([regex]::Matches($g.Text, '"Microsoft\.[^"/]+/[^"]+"').Count -eq 54)
    Check "generate ${target}: has the CloudSecure URL and tenant" ($g.Text -like "*https://cloud.example.com*" -and $g.Text -like "*cs-tenant*")
}

$g = New-Generated "-sid sub-1 -Generate az -remove"
Check "generate: -remove is refused" ($g.Code -eq 1 -and $g.Text -like "*does not support -remove*")
$g = New-Generated "-sid sub-1 -Generate az -storageAccounts illumiosa1"
Check "generate: storage account must be a resource ID" ($g.Code -eq 1 -and $g.Text -like "*is not a resource ID*")
$g = New-Generated "-Generate az"
Check "generate: needs -sid or -tid" ($g.Code -eq 1)
$g = New-Generated "-sid sub-1 -Generate az -DryRun"
Check "generate: cannot be combined with -DryRun" ($g.Code -eq 1)

$out = Join-Path $work "setup.sh"
$g = New-Generated "$full -Generate az -OutFile $out"
Check "generate -OutFile: writes the file with unix line endings" ((Test-Path $out) -and (Get-Content $out -Raw) -notlike "*`r*" -and (Get-Content $out -First 1) -eq "#!/usr/bin/env bash")

# the generated PowerShell script parses and does the same as the normal run
$variants = [ordered]@{
    "new app"        = $full
    "tenant"         = "-tid tenant-1 $cs -nsg"
    "existing app"   = "-sid sub-1 $cs -existingAppId app-9 -existingAppSecret APPSECRET -nsg -nsgRoleName 'My NSG Role'"
    "nsg role id"    = "-sid sub-1 $cs -nsg -nsgRoleId 'id-of-My NSG Role'"
    "add to app"     = "-sid sub-1 $cs -clientId app-9 -azfw -storageAccounts $sa"
    "rotate secret"  = "-sid sub-1 $cs -clientId app-9 -rotateSecret"
    "no cloudsecure" = "-sid sub-1 -clientId app-9 -nsg"
    "env only"       = "-sid sub-1 -azfw"
}
foreach ($v in $variants.Keys) {
    $ps = Join-Path $work "setup-$($v -replace ' ', '-').ps1"
    $g = New-Generated "$($variants[$v]) -Generate ps -OutFile '$ps'"
    $errs = $null
    [System.Management.Automation.Language.Parser]::ParseFile($ps, [ref]$null, [ref]$errs) | Out-Null
    Check "generate ps ($v): parses" ($g.Code -eq 0 -and $errs.Count -eq 0)
}

$env:ILLUMIO_KEY = "KEY1"; $env:ILLUMIO_TOKEN = "TOKEN1"; $env:ILLUMIO_APP_SECRET = "APPSECRET"
$env:ILLUMIO_TENANT_ID = ""; $env:ILLUMIO_API = ""
$live = Invoke-Script $full
$gen = Invoke-Script "" @{} (Join-Path $work "setup-new-app.ps1")
# the normal run registers the provider once per role, the generated script once
$normalize = { param($log) @($log | Where-Object { $_ -notlike "Register-AzResourceProvider*" } | ForEach-Object { $_ -replace '"', '' } | Sort-Object) -join "`n" }
Check "generate ps (new app): makes the same changes as the normal run" ($gen.Code -eq 0 -and $gen.Log.Count -gt 8 -and (& $normalize $gen.Log) -eq (& $normalize $live.Log))
foreach ($v in "existing app", "nsg role id", "add to app", "rotate secret", "tenant") {
    $state = @{ roles = @{ "My NSG Role" = @() } }
    $live = Invoke-Script $variants[$v] $state
    $gen = Invoke-Script "" $state (Join-Path $work "setup-$($v -replace ' ', '-').ps1")
    Check "generate ps ($v): makes the same changes as the normal run" ($gen.Code -eq 0 -and $gen.Log.Count -gt 0 -and (& $normalize $gen.Log) -eq (& $normalize $live.Log))
}
$env:ILLUMIO_KEY = ""
$gen = Invoke-Script "" @{} (Join-Path $work "setup-new-app.ps1")
Check "generate ps: stops when a required environment variable is missing" ($gen.Log.Count -eq 0 -and $gen.Out -like "*ILLUMIO_KEY*")
$env:ILLUMIO_KEY = "KEY1"

# the generated bash script runs against fake az and curl commands
if (Get-Command bash -ErrorAction SilentlyContinue) {
    $bin = Join-Path $work "bin"
    New-Item -ItemType Directory -Path $bin | Out-Null
    Set-Content -Path "$bin/az" -Value @'
#!/usr/bin/env bash
# one line per call, also when an argument has several lines
echo "az $(printf '%s' "$*" | tr '\n' ' ')" >> "$FAKE_LOG"
case "$*" in
  "account show"*) echo "tenant-1" ;;
  "ad app create"*) echo "app-1" ;;
  "ad app credential reset"*) echo "s3cr3t" ;;
  "ad sp show"*) [ -n "${FAKE_SP_EXISTS:-}" ] || exit 1; echo "sp-1" ;;
  "ad sp create"*) echo "sp-1" ;;
  "role definition list"*) if [ -f "$FAKE_DIR/role" ]; then echo "role-guid"; fi ;;
  "role definition create"*) touch "$FAKE_DIR/role" ;;
esac
exit 0
'@
    Set-Content -Path "$bin/curl" -Value @'
#!/usr/bin/env bash
echo "curl $*" >> "$FAKE_LOG"
'@
    chmod +x "$bin/az" "$bin/curl"
    $env:PATH = "$bin$([System.IO.Path]::PathSeparator)$env:PATH"
    $env:FAKE_DIR = $work

    $n = 0
    foreach ($v in $variants.Keys) {
        $n++
        $sh = Join-Path $work "setup-$n.sh"
        $g = New-Generated "$($variants[$v]) -Generate az -OutFile $sh"
        bash -n $sh
        Check "generate az ($v): is valid bash" ($g.Code -eq 0 -and $LASTEXITCODE -eq 0)
        if (Get-Command shellcheck -ErrorAction SilentlyContinue) {
            $findings = shellcheck $sh | Out-String
            Check "generate az ($v): passes shellcheck" ($LASTEXITCODE -eq 0) $findings
        }
    }

    function Invoke-Bash {
        param($file)
        $env:FAKE_LOG = Join-Path $work "fake-$([guid]::NewGuid()).log"
        Remove-Item "$work/role" -ErrorAction SilentlyContinue
        $out = bash $file 2>&1 | Out-String
        $log = if (Test-Path $env:FAKE_LOG) { @(Get-Content $env:FAKE_LOG) } else { @() }
        return [pscustomobject]@{ Out = $out; Code = $LASTEXITCODE; Log = $log }
    }
    $assign = "az role assignment create --assignee-object-id sp-1 --assignee-principal-type ServicePrincipal --role"

    $b = Invoke-Bash (Join-Path $work "setup-1.sh")
    Check "bash (new app): runs to the end" ($b.Code -eq 0 -and $b.Out -like "*All steps*") $b.Out
    Check "bash (new app): selects the subscription first" ($b.Log[0] -eq "az account set --subscription sub-1")
    Check "bash (new app): creates app, secret, principal" ($b.Log -contains "az ad app create --display-name Illumio-CloudSecure-Access --query appId -o tsv" -and @($b.Log -like "az ad app credential reset --id app-1 --append --display-name illumio --end-date 20*").Count -eq 1 -and $b.Log -contains "az ad sp create --id app-1 --query id -o tsv")
    Check "bash (new app): assigns Reader, storage, NSG and firewall roles" ($b.Log -contains "$assign Reader --scope $sub --output none" -and $b.Log -contains "$assign Storage Blob Data Reader --scope $sa --output none" -and $b.Log -contains "$assign $nsgRole --scope $sub --output none" -and $b.Log -contains "$assign $fwRole --scope $sub --output none")
    Check "bash (new app): creates the NSG role, keeps the existing firewall role" (@($b.Log -like "az role definition create *").Count -eq 1 -and $b.Out -like "*Role '$fwRole' already exists*")
    $definition = @($b.Log -like "az role definition create *")[0] -replace '^az role definition create --role-definition ', '' -replace ' --output none$', ''
    $role = ConvertFrom-Json $definition
    Check "bash (new app): role definition is valid JSON with all actions" ($role.Name -eq $nsgRole -and $role.Actions.Count -eq 23 -and $role.AssignableScopes[0] -eq $sub)
    Check "bash (new app): registers features and provider" ($b.Log -contains "az feature register --namespace Microsoft.Network --name AFWEnableStructuredLogs --output none" -and $b.Log -contains "az provider register --namespace Microsoft.Network")
    $posts = @($b.Log -like "curl *")
    Check "bash (new app): posts to CloudSecure with the service account" ($posts.Count -eq 2 -and @($posts -like "* https://cloud.example.com/api/v1/integrations/cloud_credentials --user KEY1:TOKEN1 --header X-Tenant-Id: cs-tenant *").Count -eq 2)
    $flow = ConvertFrom-Json (($posts[0] -split ' --data ')[1])
    $creds = ConvertFrom-Json (($posts[1] -split ' --data ')[1])
    Check "bash (new app): storage payload" ($flow.type -eq "AzureFlow" -and $flow.subscription_id -eq "sub-1" -and $flow.destinations[0] -eq $sa)
    Check "bash (new app): credentials payload" ($creds.type -eq "AzureRole" -and $creds.client_id -eq "app-1" -and $creds.client_secret -eq $secret -and $creds.azure_tenant_id -eq "tenant-1" -and $creds.subscription_id -eq "sub-1")

    $env:FAKE_SP_EXISTS = "1"
    $b = Invoke-Bash (Join-Path $work "setup-3.sh")
    $creds = ConvertFrom-Json ((@($b.Log -like "curl *")[0] -split ' --data ')[1])
    Check "bash (existing app): uses the app and its secret from the environment" ($b.Code -eq 0 -and @($b.Log -like "az ad app *").Count -eq 0 -and $creds.client_id -eq "app-9" -and $creds.client_secret -eq [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("APPSECRET")))
    Check "bash (existing app): assigns the given NSG role" ($b.Log -contains "$assign My NSG Role --scope $sub --output none")

    $b = Invoke-Bash (Join-Path $work "setup-6.sh")
    Check "bash (rotate secret): only creates and sends a secret" ($b.Code -eq 0 -and @($b.Log -like "az role *").Count -eq 0 -and @($b.Log -like "az ad app credential reset --id app-9 *").Count -eq 1 -and @($b.Log -like "curl *").Count -eq 1)

    $b = Invoke-Bash (Join-Path $work "setup-2.sh")
    $creds = ConvertFrom-Json ((@($b.Log -like "curl *")[0] -split ' --data ')[1])
    Check "bash (tenant): management group scope, no subscription in the payload" ($b.Code -eq 0 -and $b.Log -contains "$assign Reader --scope /providers/Microsoft.Management/managementGroups/tenant-1 --output none" -and $null -eq $creds.subscription_id -and $creds.azure_tenant_id -eq "tenant-1")

    $env:ILLUMIO_TOKEN = ""
    $b = Invoke-Bash (Join-Path $work "setup-1.sh")
    Check "bash: stops before any change when an environment variable is missing" ($b.Code -ne 0 -and $b.Log.Count -eq 0 -and $b.Out -like "*Set ILLUMIO_TOKEN first*")
}
else {
    Write-Host "SKIP  bash not found, generated az script not run" -ForegroundColor Yellow
}

Remove-Item -Recurse -Force $work
if ($fails) {
    Write-Host "`n$fails test(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "`nAll tests passed" -ForegroundColor Green
