# CF08 — Who ran it (user distribution)

**Use when:** which users executed the hash.
**Alert fields:** SHA256HashData

**Pack:** CrowdStrike Falcon (CQL)  
**Tables:** #event_simpleName=ProcessRollup2, #event_simpleName=UserIdentity  
**Inputs:** SHA256HashData="<paste sha256>"  
**Time window:** set the time picker in the top-right. These queries do NOT carry a time filter - that is how CrowdStrike's own saved searches work.  
**Scope:** Falcon console LogScale (search-all). No #repo= prefix needed there.  
**Grounding:** field names and idioms verified against CrowdStrike's public query repo (CrowdStrike/logscale-community-content) and the CQL reference at library.humio.com/crowdstrike-query-language.

ProcessRollup2 carries UserSid; the readable name comes from the
UserIdentity event, joined on UserSid the same way CrowdStrike's
"ProcessRollup2 Curation" example does it. Privileged accounts running a
hash that normal users never touch is a scope-changing finding.

```cql
#event_simpleName=ProcessRollup2
| SHA256HashData="<paste sha256>"                                   // >> EDIT
| groupBy([UserSid], function=[
      count(aid, distinct=true, as=UniqueEndpoints),
      count(aid, as=Executions),
      collect([ComputerName])
  ])
| join({
      #event_simpleName=UserIdentity
      | groupBy([UserSid], function=selectLast([UserName]))
    }, include=[UserName], field=[UserSid])
| sort(UniqueEndpoints, order=desc)
| table([UserName, UserSid, UniqueEndpoints, Executions, ComputerName])
```
