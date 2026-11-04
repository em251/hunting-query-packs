# I03 — Mailbox and file activity for the account

**Use when:** you need what was done to mail and files, not just sign-ins.
**Alert fields:** AccountUpn, AccountObjectId, IPAddress

**Pack:** Identity  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountUpn or InputAccountObjectId (REQUIRED), LookbackStart, InputSessionId  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** account-filtered and time-bounded before any aggregation.

The Office-workload detail behind I01/I02: what the account actually did to
mail and files during the session, grouped by operation so send / forward /
share / download / delete stand out from routine reads.

Two of the table's own anomaly columns are surfaced here because they are the
cheapest triage signal in cloud app data:
UncommonForUser  - "" = not enriched, "[]" = enriched and normal,
populated = attributes that are rare for this user
LastSeenForUser  - attribute -> days since last seen; negative = first ever

Keep the default window tight (usually the session, not the week) - this is a
detail query, not a sweep.

```kql
let LookbackStart = ago(24h);
let LookbackEnd   = now();
let InputAccountUpn      = "";
let InputIpAddress       = "";   // optional: everything this host touched
let InputAccountObjectId = "";
let InputSessionId = "";
let OfficeApplications = dynamic([
    "Microsoft Exchange Online", "Microsoft SharePoint Online", "Microsoft OneDrive for Business",
    "Microsoft Teams", "Microsoft 365", "Office 365"
]);
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputSessionId) or tostring(SessionData.InLineSessionId) =~ InputSessionId or tostring(RawEventData.AppAccessContext.AADSessionId) =~ InputSessionId)
| where (isempty(InputAccountUpn)      or AccountId =~ InputAccountUpn)
    and (isempty(InputAccountObjectId) or AccountObjectId =~ InputAccountObjectId)
    and (isempty(InputIpAddress)      or IPAddress == InputIpAddress)
| where Application has_any (OfficeApplications)
     or ObjectType has_any ("File", "Folder", "Message", "MailItem", "Mailbox")
| extend UncommonAttributes = tostring(UncommonForUser),
         FirstTimeAttributes = tostring(LastSeenForUser)
| summarize Events           = count(),
            FirstSeen        = min(Timestamp),
            LastSeen         = max(Timestamp),
            Objects          = make_set(ObjectName, 10),
            Ips              = make_set(IPAddress, 5),
            Countries        = make_set(CountryCode, 5),
            UncommonEvents   = countif(isnotempty(UncommonAttributes) and UncommonAttributes != "[]"),
            FirstTimeEvents  = countif(FirstTimeAttributes has "\":-")   // ":-1" = first seen today
          by Application, ActionType, ObjectType, IsAdminOperation
| order by Events desc
| take 300
```
