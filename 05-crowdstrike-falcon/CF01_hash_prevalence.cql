// ============================================================================
// PACK: CrowdStrike Falcon (LogScale / CQL)  |  QUERY: CF01 - Hash scope: how many hosts, how many runs
// Events: #event_simpleName=ProcessRollup2
// EDIT:   SHA256HashData="<paste sha256>"
// Time:   set the time picker in the top-right. These queries do NOT carry a
//         time filter - that is how CrowdStrike's own saved searches work.
// Scope:  Falcon console LogScale (search-all). No #repo= prefix needed there.
// Ground: field names and idioms verified against CrowdStrike's public query
//         repo (CrowdStrike/logscale-community-content) and the CQL reference
//         at library.humio.com/crowdstrike-query-language.
// ============================================================================
// The first question on any hash: is this one host or the whole estate, and
// how long has it been running? This proves EXECUTION. For "present on disk
// but never ran" you need a file-write event, whose name varies by repo feed -
// start here, because execution is what matters.

#event_simpleName=ProcessRollup2
| SHA256HashData="<paste sha256>"                                   // >> EDIT
| groupBy([FileName, SHA256HashData], function=[
      count(aid, distinct=true, as=UniqueEndpoints),
      count(aid, as=TotalExecutions),
      count(TargetProcessId, distinct=true, as=DistinctProcesses),
      collect([ComputerName]),
      collect([UserName]),
      min(ProcessStartTime, as=FirstStart),
      max(ProcessStartTime, as=LastStart)
  ])
// CrowdStrike's own examples multiply PR2 ProcessStartTime by 1000 before
// formatTime, so treat the raw value as seconds.
| FirstStart := FirstStart*1000
| LastStart := LastStart*1000
| formatTime(format="%F %T", field=FirstStart, as="FirstSeen")
| formatTime(format="%F %T", field=LastStart, as="LastSeen")
| table([FileName, SHA256HashData, UniqueEndpoints, DistinctProcesses, TotalExecutions,
         FirstSeen, LastSeen, ComputerName, UserName])
