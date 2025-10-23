param functionAppNameprincipal string
param functionAppName string
param roleDefinitionId string
param keyVaultName string

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource keyVault_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, roleDefinitionId)
  scope:keyVault
  properties: {
    roleDefinitionId: roleDefinitionId
    principalId: functionAppNameprincipal
    principalType: 'ServicePrincipal'
  }
}
