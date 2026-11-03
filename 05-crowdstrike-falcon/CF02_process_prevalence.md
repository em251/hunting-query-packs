# CF02 — How common is this process in my environment

**Pack:** CrowdStrike Falcon (CQL)  
**Tables:** #event_simpleName=ProcessRollup2  
**Inputs:** nothing required - uncomment the FileName filter to scope to a name  
**Time window:** set the time picker in the top-right. These queries do NOT carry a time filter - that is how CrowdStrike's own saved searches work.  
**Scope:** Falcon console LogScale (search-all). No #repo= prefix needed there.  
**Grounding:** field names and idioms verified against CrowdStrike's public query repo (CrowdStrike/logscale-community-content) and the CQL reference at library.humio.com/crowdstrike-query-language.

Prevalence ranking. Sort ascending on UniqueEndpoints: the top of the list
is the rarest thing in the fleet, which is where novel tooling hides.
Two ways to use it: uncomment the name filter to answer "is this process
normal here?", or leave it off and read the rare end of the distribution.

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
// Scope to one image when you have a name; leave commented for a fleet ranking.
// | FileName=/.*(psexec|anydesk|teamviewer)\.exe$/i               // >> EDIT
| groupBy([FileName, SHA256HashData], function=[
      count(aid, distinct=true, as=UniqueEndpoints),
      count(aid, as=TotalExecutions),
      collect([ComputerName])
  ])
| sort(UniqueEndpoints, order=asc)
| head(50)
| table([FileName, SHA256HashData, UniqueEndpoints, TotalExecutions, ComputerName])
```
