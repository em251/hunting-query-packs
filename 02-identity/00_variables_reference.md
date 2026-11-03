# 

**Pack:** Identity

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 5;
let SessionTailHours = 6;               // I01-I03: how long after the last
                                        // anchored sign-in still counts as part
                                        // of the session                  // generic "suspicious enough" count

// --- primary entity ---------------------------------------------------------
let InputAccountUpn      = "";          // user, e.g. "jdoe@contoso.com"
let InputAccountObjectId = "";          // Entra object id (survives UPN changes)
let InputIpAddress       = "";          // sign-in / logon source IP
let InputCountry         = "";          // ISO country name as recorded in Country
let InputDeviceName      = "";          // endpoint name

// --- correlation / session --------------------------------------------------
let InputSessionId       = "";          // EntraIdSignInEvents.SessionId
let InputUniqueTokenId   = "";          // EntraIdSignInEvents.UniqueTokenId
let InputCorrelationId   = "";          // EntraIdSignInEvents.CorrelationId
let InputRequestId       = "";          // EntraIdSignInEvents.RequestId
let InputMcasSessionId   = "";          // CloudAppEvents.SessionData.InLineSessionId
                                        // (MCAS session-control id - NOT the Entra
                                        //  session id; separate id space)

// --- client fingerprint -----------------------------------------------------
let InputUserAgent       = "";          // exact or partial UA string
let InputApplicationId   = "";          // app / resource app id
let InputApplication     = "";          // app display name, e.g. "Microsoft Teams"

// --- service principals -----------------------------------------------------
let InputServicePrincipalName = "";     // EntraIdSpnSignInEvents.ServicePrincipalName
```
