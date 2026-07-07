# Defender Execution Chain: High-Level Operational Phases

1. **Phase Name: Event Intake And Queue Processing**

   **Scans/Checks Performed:**
   - Receives behavior-monitoring notifications for process and module activity.
   - Orders, delays, or coalesces events so process/module state is available before deeper inspection.
   - Prioritizes module-load, process-start, cleanup, and signing-related notifications.

2. **Phase Name: Process Identity Validation**

   **Scans/Checks Performed:**
   - Opens the target process with `OpenProcess` using query/inspection access.
   - Reads process creation time with `GetProcessTimes`.
   - Confirms the opened process still matches the original PID/version to avoid PID-reuse mistakes.
   - Skips later process checks if the target cannot be opened or identity validation fails.

3. **Phase Name: Module And Image Metadata Collection**

   **Scans/Checks Performed:**
   - Captures process image path and module path metadata.
   - Normalizes paths and removes duplicate path separators.
   - Resolves alternate image names and DOS/NT path aliases.
   - Enumerates hardlink names for loaded modules when hardlink checking is enabled.

4. **Phase Name: Module Trust And Friendly-File Evaluation**

   **Scans/Checks Performed:**
   - Checks whether the loaded module path matches known process image state.
   - Checks excluded-file and known-good caches.
   - Checks friendly-file cache entries using path-derived cache keys.
   - Falls back to slower friendly-file validation when cache results are unavailable.
   - Checks whether exclusion status should allow the module to be treated as trusted.
   - Marks the process for reinspection if the module is not trusted, not friendly, and not safely excluded.

5. **Phase Name: Code-Signing And Verdict Reporting**

   **Scans/Checks Performed:**
   - Reads code-signing verdict data for module events.
   - Checks signer, code-signing flags, code directory hash, and team identifier fields.
   - Emits signing/trust reports for later behavior correlation.

6. **Phase Name: Process Hollowing / Image Memory Validation**

   **Scans/Checks Performed:**
   - Opens the target process for memory queries.
   - Queries the expected image allocation span with `VirtualQueryEx`.
   - Walks executable or protected image regions in the main image span.
   - Checks whether executable image-range pages are backed by `MEM_IMAGE`.
   - Flags suspicious image replacement when executable pages in the expected image span are not image-backed.

7. **Phase Name: Privilege And Integrity Escalation Checks**

   **Scans/Checks Performed:**
   - Opens the process token with `OpenProcessToken`.
   - Reads token integrity level from the token SID.
   - Compares current integrity level against a stored baseline.
   - Reads `SeDebugPrivilege` state from token privileges.
   - Compares current `SeDebugPrivilege` state against a stored baseline.
   - Reports suspicious integrity or privilege changes.

8. **Phase Name: ASR Injection Rule Evaluation**

   **Scans/Checks Performed:**
   - Checks module and process context against ASR rule state.
   - Checks command line and image-name policy context.
   - Evaluates Office injection-related rule conditions.
   - Evaluates LSASS-related rule conditions.
   - Emits block/audit ASR notifications when rule conditions are met.

9. **Phase Name: Process Tainting And Reinspection**

   **Scans/Checks Performed:**
   - Marks a process as tainted when module trust/friendly checks fail.
   - Records taint reason and taint type.
   - Updates tracked process state for future behavior correlation.
   - Reopens or schedules reinspection of tracked processes when needed.

10. **Phase Name: Targeted And EMS Memory Scan Setup**

    **Scans/Checks Performed:**
    - Resolves process image name by PID/version.
    - Checks whether the process is excluded from memory scanning.
    - Selects full EMS process scan or targeted memory scan mode.
    - Aligns targeted memory ranges to page boundaries.
    - Caps targeted memory scan range size before scanning.
    - Starts the process memory scan and reports the scan result.

11. **Phase Name: Process Enumeration For Memory Scanning**

    **Scans/Checks Performed:**
    - Enumerates running processes with `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW`.
    - Optionally filters candidate processes by process name.
    - Opens candidate processes with `OpenProcess`.
    - Validates process creation time before scanning.
    - Runs memory scan setup on validated candidates.

12. **Phase Name: Cleanup And State Reset**

    **Scans/Checks Performed:**
    - Clears one-shot detection flags after cleanup events.
    - Closes cached process or token handles.
    - Resets hollowing, SeDebug, and integrity tracking state when the event lifecycle ends.


# ProcessScanQueue and events

**Short Answer**
No. This is not “run all scans for every notification.” `ProcessScanQueue` is a tag/state-driven dispatcher. `AnalyzeImageLoadEvent` always invokes the callback chain for accepted notifications, but the meaningful checks are gated by `INotification` tag/type, callback predicates, process-context state, exclusions, config flags, scan scenario, and one-shot “already reported” flags.

**High-Level Scan/Check Families**

| Area | SOC / Red-Team Meaning | Main Functions |
|---|---|---|
| Startup/process identity capture | Captures initial process image/module identity, fork/create metadata, parent propagation context | `CaptureStartupModuleMetadataForProcess`, `ReportParentPropagationMatches`, `UpdateParentPropagationProcessId` |
| Module/image-load reporting | Emits module-load/image events with normalized DOS paths, NT/DOS aliases, hardlink aliases, alternate names | `ClassifyImageModuleEvent`, `EmitBehaviorModuleEvent`, `EmitModuleEventWithOptionalAlias`, `EmitAlternateImageNameEvents` |
| Module trust/friendly-file check | Decides whether a loaded module is trusted/friendly/excluded; suspicious modules can taint the process | `RunFriendlyFileSlowCheck`, `FriendlyFileLookupWithDevicePathNormalize`, `IsPathInExcludedFileCache`, `MarkProcessTaintedAndNotify` |
| Process taint and reinspection | Marks process as suspicious and schedules reinspection when an untrusted module is loaded | `MarkProcessTaintedAndNotify`, `Bm_ReinspectTrackedProcess` |
| ASR/process-access checks | Emits ASR-style notifications for suspicious process access/injection patterns, including Office injection and LSASS-related paths | `EmitAsrNotification`, `QueryImageNamePolicyForProcess`, `HasAsrRuleStateForTarget`, `ResolveAsrActionOverride` |
| Process hollowing follow-up | Marks/executes hollowing checks when process-access/module state indicates eligibility | `MarkProcessEligibleForHollowingCheck`, `CheckProcessHollowing` |
| Integrity elevation check | Detects process integrity RID increasing after baseline capture | `CheckProcessIntegrityElevation`, `QueryProcessIntegrityRid`, `ReportInternalProcessAnomaly` |
| SeDebug privilege escalation check | Detects SeDebug privilege state changing after baseline capture | `CheckSeDebugPrivilegeEscalation`, `QueryTokenSeDebugPrivilegeState`, `ReportInternalProcessAnomaly` |
| Network correlation | Extracts network detection metadata into the process context for correlation | `FUN_180b03f18`, `FUN_180b0b2a0`, `FUN_180236c2c` |
| File behavior reporting | Converts file notifications into behavior/module events: rename, delete, hardlink, file open/change-style events | `ClassifyFileBehaviorNotification`, `BuildExtendedFileChangeMetadata`, `BuildExtendedFileDeleteMetadata` |
| File rule action callback | Applies/report file rule action decisions for specific file notification types | `ProcessFileRuleActionCallback` |
| Generic behavior bridge | Maps generic behavior categories into module reports: WMI, startup, integrity, RTP, folder guard, remediation, telemetry, etc. | `MapGenericBehaviorEventToModuleReport` |
| Signer/verdict metadata | Emits code-signing verdict metadata: signer, cdhash, team ID, signing flags | `ClassifyImageModuleEvent` tag `0x2d`, `FormatAnsiStringAlloc` |

**Tag-Driven Behavior**

| Tag | High-Level Handling |
|---|---|
| `0x01` ProcessStart | Startup image metadata capture; emits primary image/module report; may enumerate hardlinks; tracks recently touched path; runs cleanup checks with reason `1`. |
| `0x02` ProcessTerminate | Deferred until after image processing; updates deferred process state if needed; runs cleanup checks with reason `2`; also clears SeDebug/hollowing tracking state. |
| `0x03` ProcessCreate | Startup/module metadata capture; emits create/image behavior event; emits alias/DOS-name variants; updates parent propagation state; runs cleanup checks with reason `3`. |
| `0x04` Internal/cleanup-style | Classifier path only runs `ProcessScanCleanupChecks(4)`. |
| `0x05` ModuleLoad | Main non-primary module-load path; compares against primary image; normalizes path; checks exclusions; emits hardlink/alias module events; runs friendly/trust lookup; taints and reinspects process if module is not trusted; runs cleanup checks with reason `5`. |
| `0x06` OpenProcess/process access | Tracked process/image branch; emits process-access behavior events `0x402b`/optional `0x402c`; evaluates ASR policy/suppression/action; can emit Office-injection/LSASS-style ASR notifications; may mark process for hollowing follow-up. |
| `0x1f` NetworkDetection | Network metadata helper enriches process context, then common callback chain runs. The heavy module classifier does not appear to treat this as a normal module-load scan. |
| `0x25` subtype `0x23` Internal | Deferred until process context is initialized; not a direct scan by itself in this path. |
| `0x29` ProcessForkCount | Startup/module metadata capture; emits behavior/module event `0x409e` with fork/count-style metadata. |
| `0x2d` Signer/details | Emits signer/verdict-style module event `0x40a5`; requires valid signer detail flag. |

**What Is Always vs Conditional**

| Check | Always? | Gate |
|---|---:|---|
| Pop from per-process heap | Yes, while queue has notifications | `ProcessScanQueue` heap state |
| `AnalyzeImageLoadEvent` callback invocation | Yes for notifications that reach post-readiness path | Not reached for deferred/uninitialized cases until replay |
| Startup metadata capture | No | Only tags `0x01`, `0x03`, `0x29` |
| Network helper | No | Only tag `0x1f` |
| Module classifier | No | Callback registration plus callback accept predicate; then tag-specific branch |
| Module trust/friendly check | No | Mainly tag `0x05`; skipped for primary-image match, exclusions, config/state gates |
| Process taint/reinspect | No | Only when module is not friendly/trusted, no scan error, not excluded/suppressed |
| ASR/process-access notification | No | Tag `0x06`, process-access flags, ASR policy state, suppression state, action override |
| Integrity elevation cleanup check | Not globally | Called from `ProcessScanCleanupChecks`, but internally requires baseline/flags and not already reported |
| Hollowing cleanup check | Not globally | Requires config enabled, process marked eligible, not already reported |
| SeDebug cleanup check | Not globally | Requires config enabled, eligibility flag, baseline token state, not already reported |
| File behavior classification | No | Separate callback path and file-notification subtypes |
| Generic behavior mapping | No | Separate generic behavior callback and known behavior category |
| Cross-process propagation | No | Callback sets propagation flag; excludes start/terminate; requires related process match |

**Architectural Takeaway**

`ProcessScanQueue` is best viewed as a per-process correlation engine, not a single scanner. The core flow is:

`INotification` tag -> process-context readiness/defer logic -> optional metadata enrichment -> callback fan-out -> tag-specific classifier -> optional taint/reinspect/ASR/cleanup checks -> optional propagation to related process contexts.

From a SOC perspective, the most important detection surfaces are untrusted module loads, process tainting, ASR process-access notifications, hollowing follow-up, integrity elevation, SeDebug escalation, signer verdicts, network correlation, and file behavior events. These are selectively triggered by event type and accumulated process state, not uniformly executed for every notification.


# Setting flags on ProcessContext based on ProcessScanQueue

**Yes**
`ProcessContext` is stateful. It is not just a transient queue consumer. It stores process identity, deferred notifications, module/path evidence, taint state, anomaly baselines, and one-shot flags used to decide whether later checks should run or be suppressed.

The “suspicious process” marking is more detailed than one Boolean.

**Stored State Categories**

| Stored In ProcessContext | Purpose |
|---|---|
| Startup/image identity | Primary image path, startup module metadata, fork/create metadata, hardlink/path aliases |
| Deferred notifications | Start/terminate/internal notifications held until context initialization |
| Network correlation | Network detection metadata associated with the process |
| Related-process state | Used to propagate notifications into related process contexts |
| Module/path evidence | Recently observed image/module paths and alias-derived module reports |
| Taint state | Process has been marked suspicious, with taint type/reason/path |
| Reinspection state | Process is scheduled or triggered for deeper inspection |
| Integrity baseline | Initial integrity RID and whether elevation was already reported |
| Hollowing eligibility | Whether this process should be checked for hollowing and whether already reported |
| SeDebug baseline | Initial SeDebug privilege state and whether escalation was already reported |
| ASR gating state | Flags used to suppress, emit, or alter ASR/process-access notifications |

**Taint Is Not Just One Flag**

`MarkProcessTaintedAndNotify` records multiple layers of state:

| State | Meaning |
|---|---|
| `+0xa61` / `+0xa62` | Coarse “process has been tainted/reported in this mode” flags used by later ASR/suppression logic |
| `+0xa63` | Set for one taint class, especially taint type `1` |
| `+0xa64` | Set for non-type-1 taint initialization path |
| `+0x810` bitmask | Accumulates taint category bits, e.g. different taint classes map to different bit masks |
| `+0x4f0` | Stores original/primary taint type |
| `+0x4f8` | Stores associated taint reason string/path |
| `+0x498..+0x4a8` | Small history/set of taint types already recorded |
| `+0x4d8` / `+0x4e0` | Current taint/evidence state used for notification/correlation |
| `FUN_180310654` tables | Per-path/per-reason taint evidence table with bitmasks and capped growth |

So architecturally it is closer to:

`process tainted = true + taint category + taint reason/path + original taint source + category bitmask + notification history`

not just:

`process.isSuspicious = true`.

**Taint Types**

The taint function accepts a taint type and maps it into different categories:

| Taint Type | Observed Meaning |
|---|---|
| `1` | Special taint class; sets `+0xa63`, category mask `0x10`, reason/event code `0xf` |
| `2`, `3`, `4`, `5`, `6`, `8` | General suspicious-process categories; category mask `0x08`; reason depends on a mode flag |
| `9` | Separate taint class; category mask `0x40`, reason/event code `0x19` |
| Other | Generic taint category; category mask `0x20` |

In the untrusted module-load path, the classifier chooses between taint type `1` and `9` depending on classifier/friendly-file state, and stores the module path as the reason/evidence.

**Reinspection**

When an untrusted module causes tainting, the flow is:

`ClassifyImageModuleEvent` -> `MarkProcessTaintedAndNotify` -> `Bm_ReinspectTrackedProcess`

`Bm_ReinspectTrackedProcess` uses the metastore/tracked-process table keyed by PID/version. If the process is still tracked, it triggers:

`Bm_OpenAndInspectProcessById(pid, 7)`

So the process is not merely labeled. It is marked with detailed taint state and then pushed back into inspection logic.

**Cleanup/Anomaly State**

The cleanup checks also store state on `ProcessContext`:

| Check | Stored State |
|---|---|
| Integrity elevation | Baseline integrity RID, current comparison state, already-reported flag |
| Hollowing | Eligibility flag, image base/span, already-reported flag |
| SeDebug escalation | Baseline SeDebug privilege state, token/handle state, already-reported flag |

These prevent duplicate reports and make later notifications meaningful because the process accumulates historical context.

**Bottom Line**

`ProcessContext` is a correlation record. It stores enough state to answer: “Has this process already looked suspicious, why, from which path/module, under which taint class, and should later ASR/hollowing/integrity checks behave differently?” It does not appear to store a single final AV-style verdict; it stores layered evidence, flags, baselines, and reinspection triggers.


# When is a process getting tainted

Examples I can tie directly to the `ProcessScanQueue` chains:

| Example | Chain | What Gets Marked |
|---|---|---|
| Untrusted/non-friendly module load | `ProcessScanQueue -> AnalyzeImageLoadEvent -> InvokeModuleScanCallbacks -> ClassifyImageModuleEvent(tag 0x05)` | The process that loaded the module is tainted |
| Remote/thread injection behavior | `ProcessScanQueue -> callback chain -> ReportRemoteThreadInjectionBehavior/FUN_1801da920` | Usually the target process is tainted/fully monitored |
| Behavior rule explicitly requests taint | `ProcessScanQueue -> callback chain -> FUN_180b053d0 or FUN_1802c0af8` | Current or target process is tainted depending on rule context |
| Cross-process taint helper | callback identifies another tracked PID/version -> `FUN_18046da78` | Another `ProcessContext` is looked up, tainted, then reinspected |

**1. Untrusted DLL/module loaded into a process**
This is the clearest direct case.

Chain:

```text
ProcessScanQueue
  -> AnalyzeImageLoadEvent
  -> InvokeModuleScanCallbacks
  -> ModuleCallbackRouter
  -> ModuleTrustEvaluationCall
  -> ClassifyImageModuleEvent(tag 0x05)
  -> RunFriendlyFileSlowCheck / FriendlyFileLookupWithDevicePathNormalize
  -> MarkProcessTaintedAndNotify
  -> Bm_ReinspectTrackedProcess
```

High-level example:

```text
winword.exe loads C:\Users\user\AppData\Local\Temp\foo.dll
foo.dll is not excluded
foo.dll is not considered friendly/trusted
friendly-file check succeeds but result is "not trusted"
```

Then Defender marks `winword.exe` tainted and schedules reinspection.

Important gates:

```text
Loaded module must not be the primary process image
Path must not be excluded
Friendly/trust check must return "not friendly"
No scan/check error suppressing the decision
```

The taint type is not just Boolean. In this path it chooses taint type `9` or `1` depending on an internal scenario/friendly-check bit, and stores the module path/reason.

**2. Suspicious injection into another process**
There is a callback path around `ReportRemoteThreadInjectionBehavior` / `FUN_1801da920`.

High-level example:

```text
unknown.exe injects into explorer.exe
source process/image is not considered friendly
target process is tracked
target image is not the same as source image
ASR taint suppression does not suppress the event
```

Then the target process can be marked tainted/fully monitored.

The function even builds telemetry like:

```text
Process <pid> will be fully monitored because of injection from <source path>
```

Then it calls:

```text
MarkProcessTaintedAndNotify(target_process)
Bm_ReinspectTrackedProcess(target_pid_version)
```

SOC interpretation:

```text
A process receiving injection becomes more suspicious even if the suspicious artifact was originally in the injecting process.
```

**3. Behavior/rule callback marks process tainted**
Some secondary behavior callbacks carry a rule/result bit saying, effectively, “this behavior should taint the process.”

One path is `FUN_180b053d0`:

```text
if behavior_flags & 0x100000000:
    MarkProcessTaintedAndNotify(process)
    Bm_ReinspectTrackedProcess(process)
```

High-level example:

```text
A behavior classifier observes an internal behavior pattern
The rule result includes the taint bit
The process is marked tainted and requeued for deeper inspection
```

This is less semantically named in the decompile, but architecturally it is a rule-driven taint path.

**4. Rule/action result says the current process should be tainted**
Another callback path, `FUN_1802c0af8`, taints when a result byte has a specific flag:

```text
if result_flags[4] & 1:
    MarkProcessTaintedAndNotify(current_process)
    Bm_ReinspectTrackedProcess(current_process)
```

SOC-level example:

```text
A behavior/rule engine callback evaluates process behavior
The callback result says this process should be treated as suspicious
Defender stores taint state and schedules process inspection
```

**What Does Not Necessarily Taint**
These are suspicious checks, but in the observed `ProcessScanQueue` chains they are not the same as `MarkProcessTaintedAndNotify`:

| Event/check | Usually does |
|---|---|
| Integrity elevation | Reports internal anomaly, sets already-reported state |
| SeDebug privilege escalation | Reports internal anomaly, sets already-reported state |
| Hollowing check | Reports hollowing anomaly and sets hollowing-reported flag |
| Tag `0x06` ASR/process access | Emits ASR notification, may mark hollowing eligibility, but not always process taint |
| Network detection `0x1f` | Adds network correlation metadata, not direct taint by itself |

**Bottom Line**
The most concrete taint examples from this pipeline are:

1. A process loads an untrusted/non-friendly module.
2. A process is the target of suspicious injection.
3. A behavior/rule callback explicitly sets a taint bit.
4. A helper taints another tracked process by PID/version and schedules reinspection.

In each case the result is not just `suspicious=true`; Defender stores taint type, reason/path, category bits, and then usually calls `Bm_ReinspectTrackedProcess`.