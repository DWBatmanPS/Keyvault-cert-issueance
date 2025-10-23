param functionAppNameprincipal string
param functionAppName string
param keyVaultName string
param KVCertOfficerRoleId string
param KVCryptoOfficerRoleId string
param KVSecOfficerRoleId string

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource keyVault_CertOfficerroleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, KVCertOfficerRoleId)
  scope:keyVault
  properties: {
    roleDefinitionId: KVCertOfficerRoleId
    principalId: functionAppNameprincipal
    principalType: 'ServicePrincipal'
  }
}

resource keyVault_CryptoOfficerroleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, KVCryptoOfficerRoleId)
  scope:keyVault
  properties: {
    roleDefinitionId: KVCryptoOfficerRoleId
    principalId: functionAppNameprincipal
    principalType: 'ServicePrincipal'
  }
}

resource keyVault_SecOfficerroleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, KVSecOfficerRoleId)
  scope:keyVault
  properties: {
    roleDefinitionId: KVSecOfficerRoleId
    principalId: functionAppNameprincipal
    principalType: 'ServicePrincipal'
  }
}
