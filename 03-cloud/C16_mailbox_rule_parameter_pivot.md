# C16 — Rule parameter pivot: forwarding destinations across the tenant

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputRuleDestination, InputAccountId (both OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** 7-day default; five columns projected before the `mv-expand`, so only rules that carry parameters reach the expand.

Companion to C03. Expands RawEventData.Parameters (the PowerShell parameter
list of the mailbox operation) into name/value rows and pivots on the
dangerous ones, so "who is forwarding where" becomes one table.
Parameter names are the documented Exchange cmdlet parameters
(New-InboxRule / Set-Mailbox); only rules that carry Parameters survive the
expand, which is why C03 stays as the unfiltered event list.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputRuleDestination = "";
let InputAccountId       = "";
let RuleParameterNames = dynamic([
    "ForwardTo", "RedirectTo", "ForwardingSmtpAddress", "ForwardingAddress",
    "SubjectContainsWords", "BodyContainsWords", "DeleteMessage",
    "MoveToFolder", "MarkAsRead", "StopProcessingRules", "Name", "Enabled"
]);
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where Application =~ "Microsoft Exchange Online"
| where ActionType has_any ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| where isempty(InputAccountId) or AccountId =~ InputAccountId
| project Timestamp, AccountId, AccountDisplayName, ObjectName, IPAddress, CountryCode,
          RuleParameters = RawEventData.Parameters
| where isnotempty(RuleParameters)
| mv-expand Parameter = RuleParameters
// the Parameters bag is {Name,Value} in Office 365 audit records; coalesce
// tolerates lowercase variants from other connectors
| extend ParamName  = tostring(coalesce(Parameter.Name, Parameter["name"],
                                        Parameter.Key, Parameter["key"])),
         ParamValue = tostring(coalesce(Parameter.Value, Parameter["value"]))
| where isnotempty(ParamName) and ParamName in (RuleParameterNames)
| extend ParamLine = strcat(ParamName, "=", ParamValue)
| summarize RuleSettings = make_set(ParamLine, 25),
            Executions   = count(),
            FirstSeen    = min(Timestamp),
            LastSeen     = max(Timestamp),
            Ips          = make_set(IPAddress, 5),
            Countries    = make_set(CountryCode, 5)
          by AccountId, AccountDisplayName, ObjectName
| where isempty(InputRuleDestination)
     or RuleSettings has InputRuleDestination
| order by Executions desc
| take 200
```
