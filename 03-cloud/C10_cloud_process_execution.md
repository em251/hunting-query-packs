# C10 — Cloud process execution with suspicious command lines

**Pack:** Cloud  
**Tables:** CloudProcessEvents  
**Inputs:** InputHostName, InputProcessName, InputResourceId (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Runtime signal from cloud VMs / containers. The pattern list is a variable so
you can extend it without touching the query body.

```kql
let LookbackStart = ago(24h);
let LookbackEnd   = now();
let InputHostName   = "";
let InputProcessName = "";
let InputResourceId = "";
let SuspiciousPatterns = dynamic([
    "curl ", "wget ", "base64 -d", "nc -e", "/dev/tcp/", "chmod +x",
    "python -c", "sh -c", "aws sts assume-role", "gcloud auth", "az login"
]);

CloudProcessEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputHostName)   or HostName =~ InputHostName)
    and (isempty(InputProcessName) or ProcessName =~ InputProcessName)
    and (isempty(InputResourceId)  or AzureResourceId =~ InputResourceId
                                   or AwsResourceName =~ InputResourceId
                                   or GcpFullResourceName =~ InputResourceId)
| extend Suspicious = ProcessCommandLine has_any (SuspiciousPatterns)
| where Suspicious
| project Timestamp, HostName, KubernetesNamespace, ContainerName, ContainerImageName,
          ProcessName, ProcessCommandLine, ParentProcessName, AccountName,
          AzureResourceId, AwsResourceName, GcpFullResourceName, ImageDigest
| order by Timestamp desc
| take 500
```
