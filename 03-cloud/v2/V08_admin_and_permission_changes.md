# V08 — Privilege surface: admin operations and permission changes

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId, InputObjectName (both optional), 24h default  
**Performance:** 24-hour window; the action list is a variable so it can be tuned without touching the logic.

Privilege escalation in SaaS rarely needs malware: a consent grant, a role assignment or a mailbox delegation is enough. This is the short list of operations worth reviewing every day, grouped by actor and target.

The action names are Office 365 / Entra operation names as they appear in the audit stream; extend `PrivilegedActions` as you learn your tenant's vocabulary.

```kql
let LookbackStart = ago(24h);
let LookbackEnd = now();
let InputAccountId = "";
let InputObjectName = "";
let PrivilegedActions = dynamic([
    "Consent to application", "Add service principal", "Add app role assignment grant to user",
    "Add app role assignment to service principal", "Add OAuth2PermissionGrant",
    "Add delegated permission grant", "Add member to role", "Remove member from role",
    "Add-MailboxPermission", "Add-MailboxFolderPermission", "Set-Mailbox",
    "New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-TransportRule",
    "New-ApplicationAccessPolicy", "Set-AdminAuditLogConfig", "Update user", "Reset user password"
]);
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where ActionType has_any (PrivilegedActions) or IsAdminOperation
| where (isempty(InputAccountId)  or AccountId =~ InputAccountId)
    and (isempty(InputObjectName) or ObjectName has InputObjectName)
| summarize Events = count(), Actors = dcount(AccountId), ActorSample = make_set(AccountId, 10),
            Objects = make_set(ObjectName, 10), Ips = make_set(IPAddress, 5),
            Countries = make_set(CountryCode, 5), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by ActionType, Application, ObjectType
| order by Events desc
| take 200
```
