// ============================================================================
// CROWDSTRIKE FALCON PACK - INPUT REFERENCE
// CQL has no `let`, so every input is a literal you edit in place. Each query
// marks its edit point with >> EDIT. There are only six values in this pack:
//
//   SHA256HashData="<hash>"   file hash (PR2 carries SHA256HashData, and
//                             MD5HashData / SHA1HashData alongside it)
//   aid="<agent id>"          host agent id - the stable host key
//   ComputerName="<host>"     host name (see note below on FDR)
//   TargetProcessId="<pid>"   Falcon unique PID of one process
//   ParentProcessId="<pid>"   the pid a child names as its parent
//   CommandLine=/<regex>/i    command line match
//   FileName=/<regex>/i       base image name match
//
// ComputerName caveat: it is populated in the Falcon console. In raw FDR
// ProcessRollup2 arrives without it, which is why CrowdStrike's own examples
// join fdr_aidmaster.csv on aid to restore it. Every query here groups by
// both aid and ComputerName, so if the name column is blank you still get the
// correct host count - just from aid.
//
// Reading the counts:
//   count(aid, distinct=true, as=UniqueEndpoints)  -> how many hosts
//   count(aid, as=TotalExecutions)                 -> how many process runs
//   count(TargetProcessId, distinct=true, ...)     -> distinct process instances
// ============================================================================
