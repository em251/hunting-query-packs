# I18 — One IP across every identity table

**Use when:** you need everything an address touched across sign-ins, logons and directory events.
**Alert fields:** IPAddress

**Pack:** Identity  
**Tables:** EntraIdSignInEvents, IdentityLogonEvents, IdentityDirectoryEvents, EntraIdSpnSignInEvents  
**Inputs:** InputIpAddress (REQUIRED)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** each branch is time-bounded; only projected columns survive the union.

The "what else did this address touch" query for identity. Branches are
deliberately narrow (7d, single IP) so the union stays cheap.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputIpAddress = "";   // REQUIRED
union
    (EntraIdSignInEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress
     | project Timestamp, Source = "SignIn", Account = AccountUpn,
               Detail = strcat(Application, " | err ", tostring(ErrorCode), " | ", Country, "/", City),
               Device = DeviceName),
    (IdentityLogonEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress or DestinationIPAddress == InputIpAddress
     | project Timestamp, Source = "IdentityLogon", Account = AccountUpn,
               Detail = strcat(Protocol, " | ", ActionType, " | ", tostring(DeviceName)),
               Device = DestinationDeviceName),
    (IdentityDirectoryEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress or DestinationIPAddress == InputIpAddress
     | project Timestamp, Source = "DirectoryEvent", Account = AccountUpn,
               Detail = strcat(ActionType, " | ", Application),
               Device = DeviceName),
    (EntraIdSpnSignInEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress
     | project Timestamp, Source = "SpnSignIn", Account = ServicePrincipalName,
               Detail = strcat(Application, " | ", ResourceDisplayName),
               Device = tostring(IsManagedIdentity))
| order by Timestamp desc
| take 1000
```
