## Endpoint

**`GET /roleManagement/directory/roleAssignments`** — the unified role management API that returns Azure AD / Entra directory role assignments (one object per principal–role–scope binding).

```
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
```

Each item looks like:

```json
{
  "@odata.context": ".../roleManagement/directory/roleAssignments",
  "id": "Y_lGlobalAdminr_1a4e6d0f-..._xxxxxxxx-...-...",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "principalId": "4ee7ed38-8a46-4f0a-9b3d-1c7e2a9f5d11",
  "directoryScopeId": "/"
}
```

- `roleDefinitionId` → resolve via `GET /roleManagement/directory/roleDefinitions/{id}`
- `principalId` → resolve via `GET /directoryObjects/{id}` (user, group, service principal)

## Required permission scope

| Permission | Type | Notes |
|---|---|---|
| **`RoleManagement.Read.Directory`** | Delegated **and** Application | **Least privilege — recommended** |
| `Directory.Read.All` | Delegated and Application | Also accepted, broader |
| `RoleManagement.ReadWrite.Directory` | Delegated and Application | Only needed to create/delete assignments |

Admin consent is required for the application flow. For delegated calls, the signed-in user must themselves hold an appropriate directory role (e.g., Global Reader / Privileged Role Administrator) — otherwise the call returns `403`.

## One request example

```bash
curl -s -G "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --data-urlencode "\$filter=principalId eq '4ee7ed38-8a46-4f0a-9b3d-1c7e2a9f5d11'" \
  --data-urlencode "\$select=id,roleDefinitionId,principalId,directoryScopeId" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Accept: application/json"
```

Equivalent HTTP request:

```http
GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '4ee7ed38-8a46-4f0a-9b3d-1c7e2a9f5d11'&$select=id,roleDefinitionId,principalId,directoryScopeId HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...
Accept: application/json
```

## Related (older) directoryRoles endpoints

If you only need *activated* roles and their members rather than raw assignment records:

- `GET /directoryRoles` — activated directory roles (needs `Directory.Read.All`)
- `GET /directoryRoles/{id}/members` — members of a role (needs `Directory.Read.All`)

`/roleManagement/directory/roleAssignments` is the better choice for auditing "who has what role," since it returns assignments even for roles that aren't currently activated and supports `$filter` on `principalId` / `roleDefinitionId`.