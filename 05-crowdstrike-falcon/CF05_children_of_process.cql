// ============================================================================
// PACK: CrowdStrike Falcon (LogScale / CQL)  |  QUERY: CF05 - Children of a process (what it spawned)
// Events: #event_simpleName=ProcessRollup2
// EDIT:   aid="<agent id>" and ParentProcessId="<parent pid>"
// Time:   set the time picker in the top-right. These queries do NOT carry a
//         time filter - that is how CrowdStrike's own saved searches work.
// Scope:  Falcon console LogScale (search-all). No #repo= prefix needed there.
// Ground: field names and idioms verified against CrowdStrike's public query
//         repo (CrowdStrike/logscale-community-content) and the CQL reference
//         at library.humio.com/crowdstrike-query-language.
// ============================================================================
// Every child whose ParentProcessId points at the process you are looking at.
// ProcessRollup2 does not carry the parent's command line, so if you only have
// a name, find the parent with CF06 first and take its TargetProcessId.

#event_simpleName=ProcessRollup2
| aid="<agent id>"                                                 // >> EDIT
| ParentProcessId="<parent pid>"                                   // >> EDIT
| groupBy([aid, ComputerName, ParentProcessId, TargetProcessId, FileName, CommandLine], function=[
      count(aid, as=Runs),
      min(ProcessStartTime, as=FirstStart)
  ])
| sort(FirstStart, order=asc)
| table([ComputerName, ParentProcessId, TargetProcessId, FileName, CommandLine, Runs, FirstStart])
