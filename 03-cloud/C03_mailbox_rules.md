# C03 — Mailbox rules and delegation

**Use when:** BEC persistence is suspected - forwarding rules, hidden rules, delegation.
**Alert fields:** AccountId, ObjectName

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId, InputObjectName, InputRuleDestination (all OPTIONAL), InputIpAddress, InputSessionId  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Post-compromise persistence in Exchange Online: forwarding rules, hidden
rules, mailbox delegation. The valuable column is RawEventData.Parameters -
the PowerShell parameter list of the operation, which is where the attacker's
forwarding destination actually lives.
This is the pattern Microsoft's own alert-grading playbook for suspicious
inbox forwarding rules uses (RuleConfig = RawEventData.Parameters).

```kql
let LookbackStart = ago(14d);
let LookbackEnd   = now();
let InputAccountId       = "";
let InputObjectName      = "";
let InputRuleDestination = "";   // external address or domain seen in the rule
let InputIpAddress = "";
let InputSessionId = "";
let MailboxPersistenceActions = dynamic([
    "New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Remove-InboxRule",
    "Set-Mailbox", "Add-MailboxPermission", "Remove-MailboxPermission",
    "Add-MailboxFolderPermission", "Set-MailboxAutoReplyConfiguration",
    "New-TransportRule", "Set-TransportRule"
]);
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputIpAddress) or IPAddress == InputIpAddress)
| where (isempty(InputSessionId) or tostring(SessionData.InLineSessionId) =~ InputSessionId or tostring(RawEventData.AppAccessContext.AADSessionId) =~ InputSessionId)
| where ActionType has_any (MailboxPersistenceActions)
| where (isempty(InputAccountId)  or AccountId =~ InputAccountId)
    and (isempty(InputObjectName) or ObjectName has InputObjectName)
| extend RuleConfig = tostring(RawEventData.Parameters)
| where isempty(InputRuleDestination) or RuleConfig has InputRuleDestination
| project Timestamp, ActionType, AccountId, AccountDisplayName, IPAddress,
          CountryCode, City, Isp, UserAgent, IsAdminOperation, IsImpersonated,
          ObjectType, ObjectName, RuleConfig = RawEventData.Parameters,
          RawEventData
| order by Timestamp desc
| take 500
```
