// ============================================================================
// PACK: CrowdStrike Falcon (LogScale / CQL)  |  QUERY: CF09 - Rarest process/parent pairs in the fleet (novelty sweep)
// Events: #event_simpleName=ProcessRollup2
// EDIT:   the endpoint threshold (default <= 3)
// Time:   set the time picker in the top-right. These queries do NOT carry a
//         time filter - that is how CrowdStrike's own saved searches work.
// Scope:  Falcon console LogScale (search-all). No #repo= prefix needed there.
// Ground: field names and idioms verified against CrowdStrike's public query
//         repo (CrowdStrike/logscale-community-content) and the CQL reference
//         at library.humio.com/crowdstrike-query-language.
// ============================================================================
// The standing hunt: everything that exists on almost no hosts. This is where
// commodity tooling, freshly dropped loaders and attacker binaries show up
// before anyone writes a detection. Run it weekly and diff the output.

#event_simpleName=ProcessRollup2 event_platform=Win
| groupBy([FileName, ParentBaseFileName, SHA256HashData], function=[
      count(aid, distinct=true, as=UniqueEndpoints),
      count(aid, as=TotalExecutions),
      collect([ComputerName])
  ])
| UniqueEndpoints <= 3                                              // >> EDIT threshold
| sort(UniqueEndpoints, order=asc)
| head(200)
| table([UniqueEndpoints, TotalExecutions, FileName, ParentBaseFileName, SHA256HashData, ComputerName])
