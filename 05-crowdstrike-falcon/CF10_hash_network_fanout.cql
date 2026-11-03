// ============================================================================
// PACK: CrowdStrike Falcon (LogScale / CQL)  |  QUERY: CF10 - What the process talked to: DNS + IPv4 under one Falcon PID
// Events: #event_simpleName=ProcessRollup2, NetworkConnectIP4, DnsRequest
// EDIT:   SHA256HashData="<paste sha256>"
// Time:   set the time picker in the top-right. These queries do NOT carry a
//         time filter - that is how CrowdStrike's own saved searches work.
// Scope:  Falcon console LogScale (search-all). No #repo= prefix needed there.
// Ground: field names and idioms verified against CrowdStrike's public query
//         repo (CrowdStrike/logscale-community-content) and the CQL reference
//         at library.humio.com/crowdstrike-query-language.
// ============================================================================
// Ties execution to egress. falconPID is the join key: TargetProcessId on the
// process event, ContextProcessId on the network and DNS events - the same
// normalization CrowdStrike uses in "Combine ProcessRollup2 and NetworkConnectIP4
// Events". selfJoinFilter keeps only PIDs that appear in the process set AND in
// the network/DNS set, so you see what this binary actually talked to.

// >> EDIT - replace the hash below
(#event_simpleName=ProcessRollup2 SHA256HashData="<paste sha256>") OR (#event_simpleName=NetworkConnectIP4) OR (#event_simpleName=DnsRequest)
| falconPID := TargetProcessId
| falconPID := ContextProcessId
| selfJoinFilter([aid, falconPID],
      where=[{#event_simpleName=ProcessRollup2},
             {#event_simpleName=NetworkConnectIP4},
             {#event_simpleName=DnsRequest}],
      prefilter=true)
// one row per distinct observation; drop ComputerName from the list if your
// feed does not populate it (raw FDR PR2)
| groupBy([aid, ComputerName, falconPID, ImageFileName, CommandLine,
          RemoteAddressIP4, RemotePort, DomainName], limit=max)
| head(500)
