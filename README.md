# Key Vault Certificate Issuance (Let’s Encrypt via Azure Functions)

Automates issuance and renewal of TLS certificates from Let’s Encrypt using DNS-01 challenges against Azure DNS, then imports them into Azure Key Vault. Built on .NET 8 isolated Azure Functions with managed identity (no shared storage keys).

## Features

- Orders certificates (SAN list) using ACME protocol (Certes).
- Supports Let’s Encrypt production and staging environments.
- Automatically renews certificates nearing expiry (timer trigger).
- Identity-based Azure Storage (blob) fallback for ACME account key if Key Vault secret not configured.
- Structured JSON responses (success + error envelopes).
- Staging chain leaf-only fallback (when intermediates unavailable).
- Separate secret names for staging vs production accounts.

## Function Endpoints

| Function | Trigger | Purpose |
|----------|---------|---------|
| RegosterAccountFunction | HTTP POST | Registers an account with Lets Encrypt |
| OrderCertificateFunction | HTTP POST | Issue a new certificate for requested domains |
| RenewCertificateFunction | Timer | Check existing Key Vault cert; renew if near expiry |

### Sample Order Request (HTTP POST)

``` http
POST /OrderCertificateFunction
```

### Sample Success Response

```
{
  "success": true,
  "data": {
    "primaryDomain": "example.com",
    "sanList": "example.com,www.example.com",
    "version": "2025-10-23T12-45-00Z",
    "leafOnly": false,
    "renewed": false
  }
}
```

### Sample Error Response

```
{
  "success": false,
  "error": {
    "code": "dns_challenge_failed",
    "message": "ACME DNS-01 validation failed for one or more domains.",
    "detail": "Authorization timed out after 120 seconds."
  }
}
```

## Environment Variables

Minimum required to run:

| Name | Description | Example |
|------|-------------|---------|
| FUNCTIONS_WORKER_RUNTIME | The function runtime. This must be defined as dotnet-isolated | dotnet-isolated |
| DOMAIN_NAME | The root zone name | contoso.com |
| LE_EMAIL | The email account used to register with Let's Encrypt | John@contoso.com |
| KEYVAULT_NAME | Name of the target Key Vault | examplekeyvault |
| RESOURCE_GROUP | Resource group containingthe Key Vault | kv-rg |
| AZURE_SUBSCRIPTION_ID | Subscription ID for the Azure Deployment | 00000000-0000-0000-0000-000000000000 |
| KEYVAULT_CERTIFICATE_NAME | Key Vault certificate name to import versions into | wildcard-example-com |
| ACCOUNT_KEY_SECRET_NAME | Name for the Lets Encrypt account key that is stored in Key Vault |

Optional / advanced:

| Name | Description |
|------|-------------|
| LE_USE_STAGING | Boolean for using the Let's Encrypt Staging environment. |
| LE_VERBOSE | Boolean for verbose logging |
| LE_DRY_RUN | "true" dry run and not complete any certificate orders. This is for testing purposes |
| LEAF_ONLY_FALLBACK | "true" to force leaf-only PFX when intermediates fail |
| ROOT_CERT_PEM | PEM string for root (if you must include manually) |
| CLEANUP_DNS | Boolean for disabling dns record cleanup | 
| PFX_PASSWORD | String for the password for when the certificate is stored as a PFX temporarily |
| ADDITIONAL_NAMES | String for setting additinonal SANs for the certificate |
| MAX_PROPAGATION_MINUTES | Defines how long the application will sleep while waiting for DNS records to propagate | 
| MAX_CHALLENGE_MINUTES | Defines how long the application will sleep for Lets Encrypt to read the challenge |

## ACME Account Secret Naming Logic

When calling the account ensure routine (see `AcmeAccountService`):

Precedence for production (similar for staging):
1. `ACCOUNT_KEY_SECRET_NAME_PROD`
2. Legacy provided `secretName` parameter
3. Blob fallback (`account-prod.pem`)

Staging suffix: if using legacy `secretName`, a `-staging` suffix is added automatically.

To rotate the ACME account key: delete the secret (or blob) and reissue a certificate—new account + key will be created.

## Managed Identity Permissions

Assign the Function App’s managed identity:

- Key Vault: Certificate Issuer (optional if using import only) + Secrets Get/Set (Azure role: Key Vault Secrets Officer or Key Vault Administrator).
- Storage Account: Blob Data Contributor (for `acme-accounts` container + host blobs).
- DNS Zone: DNS Zone Contributor (to create/remove `_acme-challenge` TXT records).

Example (PowerShell):

```powershell
# Replace with real IDs / names
$identityPrincipalId = "<function-managed-identity-object-id>"
New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName "DNS Zone Contributor" -Scope "/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Network/dnszones/example.com"
New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName "Key Vault Secrets Officer" -Scope "/subscriptions/<subId>/resourceGroups/<kvRg>/providers/Microsoft.KeyVault/vaults/my-kv"
New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName "Storage Blob Data Contributor" -Scope "/subscriptions/<subId>/resourceGroups/<storageRg>/providers/Microsoft.Storage/storageAccounts/mystorageacct"
```

## Local Development

Requirements:
- .NET 8 SDK
- Azure CLI or Az PowerShell (for identity auth)
- (Optional) Azurite for local storage; real Azure DNS + Key Vault still required for ACME DNS-01.

Run:

``` shell
dotnet restore
dotnet build
func start
```

If using managed identity locally, you'll instead authenticate via your developer credentials (DefaultAzureCredential chain). Ensure you have equivalent RBAC roles in a dev subscription.

## Deployment (Basic)

Assuming a Bicep file `deployment.bicep` provisioning:

- Storage account (allowSharedKeyAccess=false recommended)
- Function App (Linux Consumption or Premium)
- Key Vault
- DNS zones / RBAC

Deploy (example):

```powershell
New-AzResourceGroup -Name cert-rg -Location eastus
New-AzDeployment -Name certDeploy -ResourceGroupName cert-rg -TemplateFile .\deployment.bicep -TemplateParameterFile .\templateparams.bicepparam
```

Configure application settings afterward:

``` Azure CLI
az functionapp config appsettings set -g cert-rg -n my-cert-func `
  --settings KEYVAULT_URI=https://my-kv.vault.azure.net/ APP_STORAGE_ACCOUNT_NAME=mystorageacct CERTIFICATE_NAME=wildcard-example-com CERT_RENEWAL_THRESHOLD_DAYS=15
```

## Renewal Behavior

Timer schedule (see `RenewCertificateFunction`): every 2 days at 02:00 UTC (cron `0 0 2 */2 * *`). It:
1. Reads current Key Vault certificate.
2. Determines remaining days until expiry.
3. Orders a new certificate if within threshold.
4. Tags new version (e.g., `renewed=true`, `sanList=...`, `leafOnly=true` when fallback used).

To force a test renewal, temporarily set `CERT_RENEWAL_THRESHOLD_DAYS` high (e.g., 999) or adjust the cron schedule during development.

## PFX Creation & Chain Handling

- Attempts to build full chain from Let’s Encrypt.
- If staging chain incomplete, falls back to leaf-only and tags `leafOnly=true`.


## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `KeyBasedAuthenticationNotPermitted` | Storage account disallows key auth but connection string used | Ensure identity-based configuration and remove connection string |
| DNS TXT never validates | Propagation delay or wrong zone RG/sub | Verify `_acme-challenge` record existence and correct subscription |
| `account_load_error` from Key Vault | Secret name mismatch or not created | Set `ACCOUNT_KEY_SECRET_NAME_PROD/STAGING` or allow service to create |
| Leaf-only cert | Staging chain incomplete | Accept leaf; for prod ensure full chain or retry later |
| 429-like rate concerns | Too many orders close together | Implement external throttling—Let’s Encrypt has rate limits |

## Extending

Potential next steps:

- Multi-zone support (per-zone Key Vault and ACME account).
- Global rate limiting (e.g., ≤300 issuance events / 3h).
- Manual early reorder endpoint with optional revocation.
- Distributed locking (blob lease) for account creation & DNS challenge concurrency.

## Disclaimer

Use Let’s Encrypt staging for testing to avoid hitting production rate limits. Carefully manage zones and SAN counts—wildcard issuance requires DNS-01 challenge per zone.

---

Feel free to adapt paths and names; this README reflects current single-zone implementation with forward-looking notes.