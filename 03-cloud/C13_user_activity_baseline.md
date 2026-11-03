# C13 — Is this normal for the user? 30-day baseline by ISP / country / user agent

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountObjectId or InputAccountId (REQUIRED)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

The question every cloud alert turns on: has this user ever done this from
here? Microsoft's inbox-forwarding playbook answers it with make-series over
the user's own history - the alert itself is excluded from the baseline.
Change the 'by' field to ISP, CountryCode or UserAgent depending on what the
alert flagged, and render as a time chart.

```kql
let AlertTime = now();
let Timeback  = 30d;
let InputAccountObjectId = "";   // REQUIRED - stable across UPN changes
let InputAccountId       = "";   // fallback if you only have the UPN

CloudAppEvents
| where Timestamp between ((AlertTime - Timeback) .. (AlertTime - 1h))
| where (isnotempty(InputAccountObjectId) and AccountObjectId =~ InputAccountObjectId)
     or (isnotempty(InputAccountId) and AccountId =~ InputAccountId)
| where isnotempty(Isp)
| make-series ActivityCount = count() default = 0
      on Timestamp from (AlertTime - Timeback) to (AlertTime - 1h) step 12h
      by Isp
| order by array_sum(ActivityCount) desc
| take 20
```
