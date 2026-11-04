# V09 — App-initiated activity

**Use when:** what an application did on behalf of users, and whether it impersonated.
**Alert fields:** OAuthAppId, ApplicationId

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputOAuthAppId, InputApplicationId (optional), 7d default  
**Performance:** filter on the app identifiers first; the actor rollup is capped.

When the identity is an application rather than a person, `AccountType` is Application/System and `OAuthAppId` is populated. This isolates that traffic so you can see which users an app acted for, and whether it impersonated anyone.

Pairs with the OAuth queries in the parent pack: those find the grant, this shows the behaviour afterwards.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputOAuthAppId = "";
let InputApplicationId = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(OAuthAppId) or AccountType has_any ("Application", "System") or IsImpersonated
| where (isempty(InputOAuthAppId)   or OAuthAppId =~ InputOAuthAppId)
    and (isempty(InputApplicationId) or tostring(ApplicationId) =~ InputApplicationId)
| summarize Events = count(), Users = dcount(AccountId), UserSample = make_set(AccountId, 10),
            Actions = make_set(ActionType, 10), Objects = make_set(ObjectName, 5),
            Ips = make_set(IPAddress, 5), Impersonated = countif(IsImpersonated),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by OAuthAppId, Application, AccountType
| order by Events desc
| take 200
```
