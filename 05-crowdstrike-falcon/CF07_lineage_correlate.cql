// ============================================================================
// PACK: CrowdStrike Falcon (LogScale / CQL)  |  QUERY: CF07 - Three-generation lineage with correlate()
// Events: #event_simpleName=ProcessRollup2
// EDIT:   the parent FileName regex and the child FileName regex
// Time:   set the time picker in the top-right. These queries do NOT carry a
//         time filter - that is how CrowdStrike's own saved searches work.
// Scope:  Falcon console LogScale (search-all). No #repo= prefix needed there.
// Ground: field names and idioms verified against CrowdStrike's public query
//         repo (CrowdStrike/logscale-community-content) and the CQL reference
//         at library.humio.com/crowdstrike-query-language.
// ============================================================================
// correlate() is CrowdStrike's own idiom for lineage (see "Using correlate()
// to hunt process lineage"). Each named block is a subquery; the <=> operator
// ties child.aid to parent.aid and child.ParentProcessId to
// parent.TargetProcessId. sequence=true requires the order in time,
// within=10m keeps it tight - widen only if you have a slow chain.

correlate(
    grandparent: {
        #event_simpleName=ProcessRollup2 event_platform=Win
        FileName=/.*winword\.exe$/i                                // >> EDIT
        CommandLine=*
    } include: [cid, aid, TargetProcessId, ParentProcessId, UserName, ComputerName, FileName, CommandLine],
    parent: {
        #event_simpleName=ProcessRollup2 event_platform=Win
        FileName=/.*cmd\.exe$/i                                    // >> EDIT
        CommandLine=*
        | aid <=> grandparent.aid
        | ParentProcessId <=> grandparent.TargetProcessId
    } include: [cid, aid, TargetProcessId, ParentProcessId, UserName, ComputerName, FileName, CommandLine],
    child: {
        #event_simpleName=ProcessRollup2 event_platform=Win
        FileName=/.*powershell\.exe$/i                             // >> EDIT
        CommandLine=*
        | aid <=> parent.aid
        | ParentProcessId <=> parent.TargetProcessId
    } include: [cid, aid, TargetProcessId, ParentProcessId, UserName, ComputerName, FileName, CommandLine],
    sequence=true, within=10m)
| ProcessLineage := format(format="%s (%s)\n\t└ %s (%s)\n\t\t└ %s (%s)",
      field=[grandparent.FileName, grandparent.CommandLine,
             parent.FileName, parent.CommandLine,
             child.FileName, child.CommandLine])
| Endpoint := child.ComputerName
| ProcessExplorer := format("[Process Explorer](/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s)",
      field=["child.aid", "child.TargetProcessId", "child.cid"])
| table([Endpoint, ProcessLineage, ProcessExplorer])
| head(200)
