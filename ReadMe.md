# Azure Onboarding Script for Illumio CloudSecure

## Overview

This PowerShell script automates the process of onboarding Illumio CloudSecure to Azure. It handles the creation or use of Azure AD applications, role assignments, and necessary permissions for Illumio CloudSecure to interact with Azure resources.

## Recent Changes

- Added support for using an existing Azure AD application instead of creating a new one.
- Implemented flexible Network Security Group (NSG) role assignment.
- Added options to specify custom NSG roles by ID or name.

## Parameters

- `$sid`: Subscription ID
- `$tid`: Tenant ID
- `$clientId`: Existing client ID (if using an existing app)
- `$name`: Custom name for the Azure AD application
- `$secretExpirationDays`: Number of days until the secret expires (default: 365)
- `$serviceAccountKey`: Service account key for Illumio CloudSecure
- `$serviceAccountToken`: Service account token for Illumio CloudSecure
- `$csTenantId`: Illumio CloudSecure tenant ID
- `$url`: Illumio CloudSecure URL
- `$storageAccounts`: Array of storage account names
- `$azfw`: Switch to enable Azure Firewall permissions
- `$remove`: Switch to remove the Illumio app and its permissions
- `$nsg`: Switch to enable Network Security Group permissions
- `$existingAppId`: ID of an existing Azure AD application to use
- `$existingAppSecret`: Secret for the existing Azure AD application
- `$nsgRoleId`: ID of a custom NSG role to assign
- `$nsgRoleName`: Name of a custom NSG role to assign

## Usage

### Basic usage (creates new app):
```
### Using an existing app:
```
### Using a custom NSG role:
```
## NSG Role Assignment

The script now supports flexible NSG role assignment:

1. If `$nsgRoleId` is provided, it attempts to use the role with that ID.
2. If `$nsgRoleName` is provided, it attempts to use the role with that name.
3. If neither is provided or if the specified role is not found, it falls back to the default "Network Security Group Contributor" role.

This allows for more granular control over the permissions granted to the Illumio CloudSecure application in Azure.

## Notes

- Ensure you have the necessary Azure PowerShell modules installed and are logged into your Azure account before running the script.
- The script requires appropriate permissions in Azure to create/modify applications and assign roles.
- Always review and test the script in a non-production environment before using it in production.