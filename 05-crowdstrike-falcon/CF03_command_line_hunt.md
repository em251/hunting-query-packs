# CF03 — Command line hunt: who ran this, across the environment

**Pack:** CrowdStrike Falcon (CQL)  
**Tables:** #event_simpleName=ProcessRollup2  
**Inputs:** CommandLine=/<regex>/i  and optionally FileName=/<regex>/i  
**Time window:** set the time picker in the top-right. These queries do NOT carry a time filter - that is how CrowdStrike's own saved searches work.  
**Scope:** Falcon console LogScale (search-all). No #repo= prefix needed there.  
**Grounding:** field names and idioms verified against CrowdStrike's public query repo (CrowdStrike/logscale-community-content) and the CQL reference at library.humio.com/crowdstrike-query-language.

Regex against CommandLine (case-insensitive). Scope it to a process when you
know the LOLBin involved - "powershell -enc" across the estate is noise,
"-enc" only under wscript is signal.

Regex notes: /.../i is case-insensitive, \s is whitespace, and
(?<name>...) captures. Command line values are full strings, so anchor with
.* only when you need to.

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/.*\s-(enc|encodedcommand|e)\s.*/i                  // >> EDIT
| FileName=/.*powershell\.exe$/i                                   // >> EDIT (optional scope)
| groupBy([FileName, CommandLine], function=[
      count(aid, distinct=true, as=UniqueEndpoints),
      count(aid, as=TotalExecutions),
      collect([ComputerName]),
      collect([UserName])
  ])
| sort(UniqueEndpoints, order=desc)
| head(100)
| table([UniqueEndpoints, TotalExecutions, FileName, CommandLine, ComputerName, UserName])
```
