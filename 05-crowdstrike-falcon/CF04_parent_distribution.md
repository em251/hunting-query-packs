# CF04 — What launched it (parent distribution)

**Use when:** which parents spawn this hash.
**Alert fields:** SHA256HashData

**Pack:** CrowdStrike Falcon (CQL)  
**Tables:** #event_simpleName=ProcessRollup2  
**Inputs:** SHA256HashData="<paste sha256>"  
**Time window:** set the time picker in the top-right. These queries do NOT carry a time filter - that is how CrowdStrike's own saved searches work.  
**Scope:** Falcon console LogScale (search-all). No #repo= prefix needed there.  
**Grounding:** field names and idioms verified against CrowdStrike's public query repo (CrowdStrike/logscale-community-content) and the CQL reference at library.humio.com/crowdstrike-query-language.

Parent rarity is the cleanest triage signal on a hash. A binary launched by
explorer.exe on 200 hosts is user-driven; the same binary launched by
wmiprvse.exe on 2 hosts is a different conversation.

```cql
#event_simpleName=ProcessRollup2
| SHA256HashData="<paste sha256>"                                   // >> EDIT
| groupBy([FileName, ParentBaseFileName], function=[
      count(aid, distinct=true, as=UniqueEndpoints),
      count(aid, as=Executions),
      collect([ComputerName])
  ])
| sort(UniqueEndpoints, order=asc)
| table([FileName, ParentBaseFileName, UniqueEndpoints, Executions, ComputerName])
```
