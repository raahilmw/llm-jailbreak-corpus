# Microsoft Graph: List Directory Role Assignments

## Endpoint

```
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
```

This returns the collection of **directoryRoleAssignment** objects (which principal has which directory role, scoped to the tenant or an administrative unit).

> Note: The older `/directoryRoles/{id}/members` endpoint also lists role members, but `roleManagement/directory/roleAssignments` is the modern, preferred API because it exposes `principalId`, `roleDefinitionId`, `directoryScopeId`, and `appScopeId` explicitly.

## Required permission scope

Delegated (work or school account) — least privileged:
- `RoleManagement.Read.Directory`

Application permission — least privileged:
- `RoleManagement.Read.Directory`

(Read-write equivalents: `RoleManagement.ReadWrite.Directory`.)

## Example request

```http
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal
Authorization: Bearer {access-token}
```

Optional query parameters you'll often add:
- `$filter=roleDefinitionId eq '{role-definition-id}'` — e.g. filter to Global Administrator assignments
- `$expand=principal` — resolve the assignee's display name/type
- `$select=id,principalId,roleDefinitionId,directoryScopeId`

Example response (trimmed):

```json
{
  "value": [
    {
      "id": "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1",
      "principalId": "a1b2c3d4-...",
      "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
      "directoryScopeId": "/"
    }
  ]
}
```

The `roleDefinitionId` `62e90394-69f5-4237-9190-012177145e10` is the well-known ID for **Global Administrator**; `directoryScopeId: "/"` means tenant-wide.