# CF05 — Children of a process

**Use when:** what the process spawned.
**Alert fields:** aid, ParentProcessId

**Pack:** CrowdStrike Falcon (CQL)  
**Tables:** #event_simpleName=ProcessRollup2  
**Inputs:** aid="<agent id>" and ParentProcessId="<parent pid>"  
**Time window:** set the time picker in the top-right. These queries do NOT carry a time filter - that is how CrowdStrike's own saved searches work.  
**Scope:** Falcon console LogScale (search-all). No #repo= prefix needed there.  
**Grounding:** field names and idioms verified against CrowdStrike's public query repo (CrowdStrike/logscale-community-content) and the CQL reference at library.humio.com/crowdstrike-query-language.

Every child whose ParentProcessId points at the process you are looking at.
ProcessRollup2 does not carry the parent's command line, so if you only have
a name, find the parent with CF06 first and take its TargetProcessId.

```cql
#event_simpleName=ProcessRollup2
| aid="<agent id>"                                                 // >> EDIT
| ParentProcessId="<parent pid>"                                   // >> EDIT
| groupBy([aid, ComputerName, ParentProcessId, TargetProcessId, FileName, CommandLine], function=[
      count(aid, as=Runs),
      min(ProcessStartTime, as=FirstStart)
  ])
| sort(FirstStart, order=asc)
| table([ComputerName, ParentProcessId, TargetProcessId, FileName, CommandLine, Runs, FirstStart])
```
