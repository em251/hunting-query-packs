# CF06 — Parent lookup

**Use when:** what started this process.
**Alert fields:** aid, TargetProcessId

**Pack:** CrowdStrike Falcon (CQL)  
**Tables:** #event_simpleName=ProcessRollup2  
**Inputs:** aid="<agent id>" and TargetProcessId="<child pid>"  
**Time window:** set the time picker in the top-right. These queries do NOT carry a time filter - that is how CrowdStrike's own saved searches work.  
**Scope:** Falcon console LogScale (search-all). No #repo= prefix needed there.  
**Grounding:** field names and idioms verified against CrowdStrike's public query repo (CrowdStrike/logscale-community-content) and the CQL reference at library.humio.com/crowdstrike-query-language.

Point at one process and resolve its parent. The join is the same
key/field pattern CrowdStrike uses in "Use Join on Two Scoped Events":
key is the child's ParentProcessId, field is the parent's TargetProcessId.

```cql
#event_simpleName=ProcessRollup2
| aid="<agent id>"                                                 // >> EDIT
| TargetProcessId="<child pid>"                                    // >> EDIT
| ChildImage  := ImageFileName
| ChildCmd    := CommandLine
| ChildStart  := ProcessStartTime
| join({
      #event_simpleName=ProcessRollup2
      | aid="<agent id>"                                           // >> EDIT
      | ParentImage := ImageFileName
      | ParentCmd   := CommandLine
      | ParentStart := ProcessStartTime
    },
    key=[aid, TargetProcessId],
    field=[aid, ParentProcessId],
    include=[ParentImage, ParentCmd, ParentStart, UserName, ComputerName]
  )
| table([ComputerName, UserName, ParentImage, ParentCmd, ParentStart,
         ChildImage, ChildCmd, ChildStart])
```
