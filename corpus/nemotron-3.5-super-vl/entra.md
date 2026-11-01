**Endpoint**

```
GET https://graph.microsoft.com/v1.0/directoryRoleAssignments
```

This returns all directory role assignments in the tenant.  
(You can also scope it to a single role with `GET /directoryRoles/{id}/assignments`.)

**Required permission scope**

The caller needs at least one of the following:

| Permission type | Scope |
|-----------------|-------|
| Delegated (work/school account) | `Directory.Read.All` (or `Directory.ReadWrite.All`) |
| Application | `Directory.Read.All` (or `Directory.ReadWrite.All`) |

Application permissions require admin consent.

**Request example**

```http
GET https://graph.microsoft.com/v1.0/directoryRoleAssignments
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...
Content-Type: application/json
```

If successful, the response returns a collection of `directoryRoleAssignment` objects, each containing the `id`, `directoryRoleId`, and `principalId` of the assigned user or group.