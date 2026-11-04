# 

**Pack:** Cloud

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 3;
// --- actor (table-specific naming, same person) -----------------------------
let InputAccountId       = "";   // CloudAppEvents.AccountId (UPN/email)
let InputAccountUpn      = "";   // CloudKeyVaultEvents/CloudStorageAggregatedEvents.AccountUpn
let InputAccountObjectId = "";   // Entra object id
let InputIpAddress       = "";   // source IP
let InputCountryCode     = "";   // ISO-2, e.g. "NG"
let InputSessionId       = "";   // cloud: matched against BOTH id spaces -
                                  // SessionData.InLineSessionId (MCAS session control)
                                  // and RawEventData.AppAccessContext.AADSessionId
let InputUserAgent       = "";   // UA string or fragment
// --- workload ---------------------------------------------------------------
let InputApplication     = "";   // CloudAppEvents.Application, e.g. "Microsoft Exchange Online"
let InputApplicationId   = "";   // app / client id
let InputObjectName      = "";   // CloudAppEvents.ObjectName (mailbox, site, file)
let InputOAuthAppId      = "";   // OAuthAppInfo.OAuthAppId / CloudAppEvents.OAuthAppId
let InputResourceId      = "";   // Azure/AWS/GCP resource identifier
let InputDataSource      = "";   // CloudAuditEvents.DataSource: AWS / GCP / Azure / Kubernetes Audit
let InputVaultName       = "";   // CloudKeyVaultEvents.VaultName
let InputStorageAccount  = "";   // CloudStorageAggregatedEvents.StorageAccount
let InputDnsQuery        = "";   // CloudDnsEvents.DnsQuery
let InputHostName        = "";   // Cloud*Events.HostName
let InputProcessName     = "";   // CloudProcessEvents.ProcessName
// --- nested payload / entity (see C14 before hard-coding any RawEventData path)
let InputPrincipal       = "";   // CloudAuditEvents actor, resolved per platform in C06
let InputActionType      = "";   // CloudAppEvents.ActionType, e.g. "New-InboxRule"
let InputRuleDestination = "";   // mailbox rule destination (address or domain)
```
