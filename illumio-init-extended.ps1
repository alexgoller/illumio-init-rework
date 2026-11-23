# Deprecated: illumio-init.ps1 now supports -existingAppId, -existingAppSecret, -nsgRoleId and -nsgRoleName itself.
# This wrapper only forwards to it, so that existing instructions keep working.

$main = Join-Path $PSScriptRoot "illumio-init.ps1"
if (-not (Test-Path -Path $main -PathType Leaf)) {
    Write-Host "Error: illumio-init.ps1 was not found next to this script. Download it and run it with the same parameters." -ForegroundColor Red
    exit 1
}

# as before, -nsg without a role assigns the role 'Network Security Group Contributor' instead of creating one
$defaults = @{}
if ($args -contains "-nsg" -and $args -notcontains "-nsgRoleId" -and $args -notcontains "-nsgRoleName") {
    $defaults["nsgRoleName"] = "Network Security Group Contributor"
}

& $main @args @defaults
