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