# Defender Behavior Checks Around Process / Module / Memory Scanning

This note summarizes the observed `mpengine.dll` paths around the supplied stack trace. Addresses below are Ghidra image-base addresses. Runtime stack addresses were rebased from `mpengine.dll` runtime base `0x7ffeefb40000` to Ghidra base `0x180000000`.

The focus is the decision logic that leads Defender to inspect a process/module and potentially trigger memory-oriented scanning or process taint/reinspection. Cleanup-only and synchronization details are omitted unless they gate a check.

## Stack Frame Map

| Stack idx | Runtime address | Ghidra address | Function name used here | Role |
|---:|---:|---:|---|---|
| `0x03` | `0x7ffeefc781c7` | `0x1801381c7` | `AcquireProcessHandleForScan` | Opens target process and validates that the process creation time still matches the notification PID/version. |
| `0x04` | `0x7ffeefdd33d7` | `0x1802933d7` | `CheckProcessHollowing` | Uses `VirtualQueryEx` over the target image range. Flags executable image span containing non-`MEM_IMAGE` memory as `Hollow1`. |
| `0x05` | `0x7ffeefdd3010` | `0x180293010` | `ProcessScanCleanupChecks` | Runs post-event checks: EoP/integrity, hollowing, SeDebug privilege changes, then optional state reset. |
| `0x06` | `0x7ffeefc66c8e` | `0x180126c8e` | `ClassifyImageModuleEvent` | Large module/event dispatcher. Handles scan types `1`, `2`, `3`, `4`, `5`, `6`, `0x29`, `0x2d`. |

Related queue/callback frames below the supplied focus area:

| Runtime address | Ghidra address | Function name used here | Role |
|---:|---:|---|---|
| `0x7ffeefc65ae0` | `0x180125ae0` | `ModuleTrustEvaluationCall` | Callback adapter. Runs a filter predicate, then dispatches to `ClassifyImageModuleEvent` or another handler. |
| `0x7ffeefc65911` | `0x180125911` | `ModuleCallbackRouter` | Callback router. Selects `ModuleTrustEvaluationCall`, `SecondaryBehaviorCallbackRouter`, `GenericBehaviorEventCallback`, or indirect callback. |
| `0x7ffeefc6512c` | `0x18012512c` | `InvokeModuleScanCallbacks` | Iterates registered callbacks for a notification. |
| `0x7ffeefc64fd6` | `0x180124fd6` | `AnalyzeImageLoadEvent` | Preprocesses notification types, then invokes module-scan callbacks. |
| `0x7ffeefc648d5` | `0x1801248d5` | `ProcessScanQueue` | Pulls queued notifications, delays or coalesces some, then dispatches them. |

## High-Level Flow

| Phase | Function | Key checks / decisions | Result |
|---|---|---|---|
| Queue consumption | `ProcessScanQueue` | Handles notification ordering. Type `1` can be delayed until initialization/metadata is ready. Type `2` can be held separately. Some events are delayed if `a18 & 0x10` is not set. | Calls `AnalyzeImageLoadEvent` when ready. |
| Notification preprocessing | `AnalyzeImageLoadEvent` | For event types `1`, `3`, `0x29`, calls `CaptureStartupModuleMetadataForProcess` to copy startup/module metadata into process context. For type `0x1f`, processes network metadata. | Calls `InvokeModuleScanCallbacks`. |
| Callback fanout | `InvokeModuleScanCallbacks` | Iterates registered callback objects at `process_ctx + 0xc8`. A callback can request propagation/stop behavior through local output flags. | Calls `ModuleCallbackRouter` or indirect callbacks. |
| Callback routing | `ModuleCallbackRouter` | Dispatches by vtable slot: `ModuleTrustEvaluationCall`, `SecondaryBehaviorCallbackRouter`, `GenericBehaviorEventCallback`, or indirect. | Reaches `ClassifyImageModuleEvent` in this trace. |
| Main classification | `ClassifyImageModuleEvent` | Dispatches on notification type at `*(int *)&param_3[1].Flink`. | Emits behavior records, taints process, requests reinspection, or runs cleanup checks. |
| Post-event checks | `ProcessScanCleanupChecks` | Always runs EoP/integrity, hollowing, and SeDebug checks. Type `2` also resets process-side state. | May emit internal detections or update process state. |

## Process Handle Acquisition

### `AcquireProcessHandleForScan` at `0x1801381a0`

This is the frame that contains the `OpenProcess` call in the supplied stack.

| Step | Check | Details | Skip / failure behavior |
|---|---|---|---|
| Input validation | Output pointer must exist. | Null output triggers assertion/logging and returns `0x57`. | No handle. |
| Allocate wrapper | Allocates a small handle record. | Record fields include handle, access mask, process creation time, and PID. | Allocation failure returns `0xe`. |
| Access mask construction | If PID is nonzero, requested access is ORed with `0x400`; if the local open-process hardening/config helper at `0x180138584` is true, also ORed with `0xc00`. | In observed hollowing path, caller requests `0x410`; effective access is at least `0x410`, possibly with `0xc00`. | None. |
| Open target | `OpenProcess(access, FALSE, pid)`. | On failure returns `GetLastError()`. | No later checks using this handle. |
| PID/version validation | `GetProcessTimes` stores process creation time in wrapper. | Callers compare stored creation time against notification PID-version data to avoid PID reuse. | Mismatch closes handle and returns `0x57`. |

The PID creation-time check is important: most later process decisions assume the opened handle still refers to the same process instance that generated the notification.

## Post-Event Cleanup Checks

`ProcessScanCleanupChecks` at `0x180292ff4` does more than cleanup. Its first three calls are checks:

```text
CheckProcessIntegrityElevation(param_1);
CheckProcessHollowing(param_1);
CheckSeDebugPrivilegeEscalation(param_1);
```

Only after these checks does it clear state for cleanup type `2`.

### Integrity / EoP Check: `CheckProcessIntegrityElevation`

| Gate / condition | Meaning observed from code | Action |
|---|---|---|
| `process_ctx + 0x794 != 0` | EoP/integrity tracking was enabled for this process context. | Continue. |
| `process_ctx + 0x799 == 0` | Detection/report not already marked as done. | Continue. |
| `process_ctx + 0x798 == 0` | Initial integrity snapshot has not yet been stored. | Store current value when threshold condition is met. |
| `(process_ctx + 0x7a0 & 0xf) <= *(uint64 *)(process_ctx + 0x728)` | Threshold/interest test before taking initial snapshot. | Calls `QueryProcessIntegrityRid` and stores baseline at `+0x79c`; sets `+0x798 = 1`. |
| Later current integrity greater than stored baseline | Current value from `QueryProcessIntegrityRid` is greater than stored `+0x79c`. | Calls `ReportInternalProcessAnomaly(..., reason, DAT_180dc8458, 0)`. |

`ReportInternalProcessAnomaly` builds an internal detection record with fields such as `InitialInt`, `EoPInt`, and `IntegrityEnum`, then walks related process context and reports it. This is not a memory-region scan itself, but it marks/reports suspicious elevation state.

### Process Hollowing / Unbacked Executable Image Range: `CheckProcessHollowing`

This is the clearest memory-region check in the supplied stack. It uses `VirtualQueryEx` over what appears to be the main image allocation span.

| Gate / condition | Meaning | Effect |
|---|---|---|
| `DAT_1810ade21 == 0` | `MpDisableProcessHollowingChecks` is not set. | If disabled, returns immediately. |
| `process_ctx + 0x7b1 != 0` | Process context is marked as eligible for hollowing checks. | If not set, returns. |
| `process_ctx + 0x7b2 == 0` | `Hollow1` has not already been reported. | If already set, returns. |
| `AcquireProcessHandleForScan(..., 0x410) == 0` | Target process can be opened and PID/version matches. | If open/validation fails, returns. |
| `process_ctx + 0x7b8` base exists, or `FindExecutableImageSpanForHollowingCheck` can discover base/size. | Gets image allocation base and image span size. | If discovery fails, logs and returns. |

The discovery helper `FindExecutableImageSpanForHollowingCheck`:

| Step | Observed behavior |
|---|---|
| Validate process handle | Calls `EnsureProcessHandleAccess(handle_record, 0x410)`. |
| Query process image/memory seed | Calls `QueryProcessImageMemoryInfo(handle, 0, &local_78, 0x18)`. The result includes a base-related value and span size. |
| Find first executable page | Calls `VirtualQueryEx` from the allocation base and walks regions until it finds a page whose `Protect` is in an accepted executable set or equals `0x80`. |
| Return | Stores first executable region base in `process_ctx + 0x7b8` and span size in `process_ctx + 0x7c0`. |

The actual hollowing check then walks from `base = *(process_ctx + 0x7b8)` for `size = *(process_ctx + 0x7c0)`:

| Check | Code-level behavior | Decision |
|---|---|---|
| Region query succeeds | `VirtualQueryEx(process, address, &mbi, 0x30)` | Stop if query fails. |
| Protection is executable-ish | Accepted if `(Protect - 0x10) <= 0x30` and bitmask `0x1000000010001` contains that protect offset, or if `Protect == 0x80`. | Stop if protection is outside accepted set. |
| Memory type is image | Requires `mbi.Type == 0x1000000` (`MEM_IMAGE`). | If not image, reports `Hollow1`. |
| Region size nonzero | Adds `mbi.RegionSize` and continues until covered span reaches `+0x7c0`. | Stop on zero size. |

Detection action:

| Detection | Trigger | Action |
|---|---|---|
| `Hollow1` | An executable/protected page inside the expected image span is not `MEM_IMAGE`. | Calls `ReportInternalProcessAnomaly(process_ctx, 0, L"Hollow1", 1)` and sets `process_ctx + 0x7b2 = 1`. |

Interpretation constrained to the code: this check does not search all private executable memory. It specifically validates that the target image span is still backed by `MEM_IMAGE` regions. That is consistent with a process-hollowing style detection, where the original mapped image is replaced or partially replaced by non-image memory.

### SeDebug Privilege Change: `CheckSeDebugPrivilegeEscalation`

| Gate / condition | Meaning | Action |
|---|---|---|
| `DAT_1810ade22 == 0` | `MpDisableSeDebugChecks` is not set. | If disabled, return. |
| `process_ctx + 0x7b3 != 0` | SeDebug tracking is enabled for this process. | If not set, return. |
| `process_ctx + 0x7b4 == 0` | No SeDebug report has been emitted yet. | If already set, return. |
| Token open succeeds | Uses `AcquireProcessHandleForScan`, then `OpenProcessToken(..., 8, ...)`. | If token open fails, return. |
| Baseline stored | If `process_ctx + 0x7c8 == -1`, reads baseline token privilege state with `QueryTokenSeDebugPrivilegeState`. | Stores initial state. |
| Current state differs | Compares current `SeDebugPrivilege` attributes against baseline. | Emits detection and sets `+0x7b4 = 1`. |

Detection labels:

| Label | Trigger |
|---|---|
| `SeDebugEop` | Baseline was `0`, current privilege state changed. |
| `SeDebugEop1` | Baseline was `-2`, current privilege state changed. |

`QueryTokenSeDebugPrivilegeState` resolves `SeDebugPrivilege` with `LookupPrivilegeValueW`, reads token privileges, and stores the attribute value for that LUID or `0xfffffffe` if absent.

## Main Dispatcher: `ClassifyImageModuleEvent`

Dispatch value: `*(int *)&param_3[1].Flink`.

Observed cases: `1`, `2`, `3`, `4`, `5`, `6`, `0x29`, `0x2d`.

I did not find a case `0x39` in this dispatcher. The only `0x39` values encountered in these paths were telemetry/config byte offsets such as `DAT_1810aa7c8 + 0x39`, and logging IDs elsewhere.

| Type | Event / scan id | Main purpose | Important actions |
|---:|---:|---|---|
| `1` | `0x4011` | Process/module load style event with snapshot metadata. | Reports via `EmitModuleEventWithOptionalAlias`; then `ProcessScanCleanupChecks(..., 1)`. |
| `2` | none directly | Minimal cleanup / deferred processing. | Optionally calls `UpdateDeferredProcessPathState`; then `ProcessScanCleanupChecks(..., 2)`. |
| `3` | `0x4010` | Module path event. | Normalizes path, reports via `EmitBehaviorModuleEvent` / `EmitAlternateImageNameEvents`, updates module tracking, then `ProcessScanCleanupChecks(..., 3)`. |
| `4` | none directly | Cleanup-only path. | Calls `ProcessScanCleanupChecks(..., 4)`. |
| `5` | `0x4014` | Module trust/friendly/cache decision. | May mark process as tainted and request reinspection if module is not trusted/friendly/excluded. |
| `6` | `0x402b`, optional `0x402c` | Running module / ASR-heavy path. | Reports module state, handles Office/LSASS ASR rule paths, may update tracked process state. |
| `0x29` | `0x409e` | Code-signing/trust style module report. | Reports path and signing-related flags. |
| `0x2d` | `0x40a5` | Code-signing verdict formatting/reporting. | Formats verdict/signing flags/signer/cdhash/teamid and reports. |

## Dispatcher Case Details

### Type `1`: Module / Process Load Snapshot, Event `0x4011`

| Step | Check / callee | Meaning / effect |
|---|---|---|
| Build path/context | path copy helper, `SnapshotProcessContextForModuleEvent` | Copies process-context identity and path-related state under lock. |
| Optional metadata path | `RemoveAdjacentDuplicatePathSeparators` | Derives a normalized path variant if duplicate separators are present. |
| Hardlink behavior flag | `DAT_1810ade62` (`MpDisableHardlinkCheck`) | If hardlink check is enabled, expands related names using `EnumerateHardlinkNamesForPath`; otherwise emits direct report. |
| Report | `EmitModuleEventWithOptionalAlias` | Emits event and optional alias/extra path reports. |
| Follow-up tracking | If `process_ctx + 0xa65` is clear, calls `TrackRecentlyTouchedPath`. | Adds/updates path tracking. |
| Post checks | `ProcessScanCleanupChecks(..., 1)` | Runs EoP/hollowing/SeDebug checks. |

Skip/whitelist behavior seen here is mostly indirect: if metadata extraction fails, it falls back to direct reporting. Trust decisions are mainly in type `5`.

### Type `3`: Module Path Event, Event `0x4010`

| Step | Check / callee | Effect |
|---|---|---|
| Require path | Uses `param_3[0xe]` path string. | Missing path returns error. |
| Normalize path | string duplication/normalization helper. | Keeps processing even if normalization fails. |
| Optional secondary metadata | `RemoveAdjacentDuplicatePathSeparators` | If present, reports both derived and original metadata. |
| Report | `EmitBehaviorModuleEvent`, `EmitAlternateImageNameEvents` | Emits event and alternate-name expansion if enabled. |
| Optional callback | `ResolveNtPathToDosAliasForEvent` may return extra target callback. | Invokes callback if returned. |
| Post checks | `ProcessScanCleanupChecks(..., 3)` | Runs EoP/hollowing/SeDebug checks. |
| Track module | `ReportParentPropagationMatches`, `UpdateParentPropagationProcessId` | Updates module tracking using process id/version tuple. |

### Type `0x29`: Signing/Trust Report, Event `0x409e`

| Step | Check / callee | Effect |
|---|---|---|
| Resolve path | Path from `param_3[0xe]`, normalized with string duplication/normalization helper. | Fallback to original path on failure. |
| Store flags | Reads `param_3[0x20].Flink`. | Saved into event metadata. |
| Report | `EmitBehaviorModuleEvent` | Emits signing/trust-style report. |

No enforcement or taint action was apparent in this case by itself.

### Type `5`: Module Trust / Friendly / Cache Path, Event `0x4014`

This is the most important module-load trust path. It decides whether a module load is trusted/friendly/excluded and can mark the process for reinspection.

#### Initial Path And Duplicate Checks

| Check | Code behavior | Effect |
|---|---|---|
| Resolve module path | Uses `param_3[0xe]`; chooses inline or heap string. | Main path input. |
| Fetch existing process path/state | `GetProcessPrimaryImagePath(process_ctx, &old_path)` under process lock. | Old path is used for same-directory/same-module comparison. |
| Same path check | `WcsicmpAsciiFast(new_path, old_path) == 0`. | Skips further trust work and returns through cleanup path. |
| Global path cache | `DAT_1810bc1d0` / `DAT_1810bc228`, lookup `ResolveDosPathWithCache`. | Uses cached normalized path if available. |

#### Excluded / Known File Check

| Check | Function / flag | Effect |
|---|---|---|
| Excluded-file lookup | `IsPathInExcludedFileCache(path)` | Returns true if path is in a cached exclusion/known set. |
| Global skip | `DAT_1810adf19` (`MpDisableBmProcessingExcludedFileNotifications`) | If enabled and path is excluded, the main trust path is skipped/logged. |
| Trusting excluded files | `DAT_1810adec9` (`MpDisableTrustingExcludedFiles`) | Affects final trusted decision: excluded status may or may not allow trust. |

#### Same-Directory / Module-Load Context

| Check | Flag | Effect |
|---|---|---|
| Compare path component around `\` | Controlled by `DAT_1810adf6f` (`MpDisableModuleLoadSameDirectory`). | If enabled, skips this comparison. |
| Basename / directory equality | Compares `new_path` and `old_path` through `FindLastWideChar` and `WcsnicmpAsciiFast`. | Stores one of two string constants into event metadata depending on equality. |

#### Hardlink / Alternate Name Expansion

| Check | Flag / function | Effect |
|---|---|---|
| Hardlink expansion enabled | `DAT_1810ade62 == 0` (`MpDisableHardlinkCheck` not set). | Calls `EnumerateHardlinkNamesForPath` to enumerate names with `FindFirstFileNameW` / `FindNextFileNameW`. |
| Expanded report | `EmitModuleEventForHardlinkAlias` per alternate name. | Reports each alternate path. |
| Direct report | If hardlink expansion disabled or unavailable. | Uses `EmitBehaviorModuleEvent` / `EmitAlternateImageNameEvents`. |

#### Friendly Cache And Slow Check

| Check | Code behavior | Effect |
|---|---|---|
| Scenario gate | `Bm_GetCurrentScanScenario()` in `{1,2,3,4,6}` sets a local scenario flag. | Enables extra reporting for module trust decisions. |
| Directory slow-check policy | `MpDisableDllFriendlySlowCheckWinDir`, `MpDisableDllFriendlySlowCheckProgramDir`, `MpDisableDllFriendlySlowCheckAllDirs`, `MpOnlyCfaDllFriendlySlowCheckAllDirs`. | Determines whether the slow friendly check is allowed for path categories. |
| Cache-key config | `MpUseNewFriendlyCacheKey`; default is enabled on config-read failure. | Enabled builds key `L"%ls%u%u%u"`; disabled hashes path directly. |
| Friendly cache | Globals `DAT_18107f928` / `DAT_18107f930`. | Valid hit uses cached result byte at entry `+0x28`. |
| Slow friendly check suppression | `MpDisableFriendlySlowCheck`. | Can suppress the slow fallback. |
| Slow friendly fallback | `RunFriendlyFileSlowCheck`. | Performs fast/slow friendly logic, USN-style checks, and returns scan/error/exclusion flags. |
| Alternate friendly lookup | `FriendlyFileLookupWithDevicePathNormalize` -> `Bm_FriendlyFileLookup`. | Used when path source differs from normalized path object. |

Final friendly decision variables inferred from event string:

| Event field | Local variable use | Meaning |
|---|---|---|
| `IsFriendly` | `local_306` | Friendly result or cached result. |
| `IsExcluded` | `local_303` | Excluded/known result. |
| `ScanError` | `local_300._4_4_` | Error/status from friendly check. |
| trusted / not trusted | `local_308[0]` | Final decision after friendly, excluded, error, and config gates. |

Telemetry string:

```text
Module load (%ls) %ls trusted. IsFriendly:%u, IsExcluded:%u. ScanError: 0x%08lX.
```

#### Taint / Reinspection Decision

The key enforcement-style branch in type `5`:

| Condition | Action |
|---|---|
| Final trusted decision is false. | Continue. |
| Scan error is zero. | Continue. |
| Not suppressed by excluded-file trust rules. | Continue. |
| Then call `MarkProcessTaintedAndNotify(...)`. | Marks process taint and records taint reason/type. |
| Then call `Bm_ReinspectTrackedProcess(..., 1)`. | Attempts to re-open/reinspect tracked process by PID. |

`MarkProcessTaintedAndNotify` logs taint with strings like:

```text
Process %ls (PPID:%lu:%llu) is tainted: TaintType:0x%llX. TaintReason:%ls, EnableCfa:%d
```

It also updates process flags and can call follow-on callbacks. The taint type used from the type `5` path is computed as either `9` or `1` depending on a local “slow/friendly category” flag.

### Type `6`: Running Module / ASR Path, Events `0x402b` And `0x402c`

Type `6` handles module report plus ASR-style rule logic.

#### Initial Module Report

| Check | Function / field | Effect |
|---|---|---|
| Resolve metastore module info | `ResolveTrackedProcessImagePath(meta, &path, &param_3[0xe].Blink, 1)` | Gets path or module identity. |
| Exclusion skip | If `DAT_1810adf19 != 0` and `IsPathInExcludedFileCache(path) != 0`. | Skips the initial report. |
| Report event | `local_1ce = 0x402b`, `EmitBehaviorModuleEvent`. | Emits module event. |
| Optional second report | If byte at `param_3[0x1b].Flink + 4` is set. | Emits `0x402c`. |

#### ASR Office Injection Rule Branch

| Condition / function | Meaning / effect |
|---|---|
| `(param_3[0x1b].Blink & 0xc) != 0` | Enters Office-style ASR rule path. |
| Indirect predicate at `param_3` vtable slot `0x70` | If predicate says already handled/allowed, branch can skip. |
| `GetProcessPrimaryImagePathLocked`, string duplication, `GetProcessCommandLineForAsr`, `QueryProcessIntegrityRid` | Resolves process/module/command-line context for the rule. |
| `Bm_GetImageNameConfigProvider`, `QueryImageNamePolicyForProcess` | Retrieves image-name policy/config context. |
| If `HasAsrRuleStateForTarget(param_3 + 0x19) == 0` and `ShouldSuppressAsrForTaintedProcess(process_ctx) != 0` | Formats special Office block message. |

Office message:

```text
Friendly process '%ls' was blocked by ASR Office Block Injection rule, target=%ls, commandline=%ls
```

Notification suppression string:

```text
ASR notification suppressed
```

General ASR action path:

```text
EmitAsrNotification(param_3 + 0x19, action, 2, ...)
```

`EmitAsrNotification` builds an ASR notification/report. It logs action as `BLOCK` or `AUDIT`, includes target/reason/rule, and handles persisted rule state.

#### ASR LSASS Branch

| Condition / function | Meaning / effect |
|---|---|
| `(param_3[0x1b].Blink & 8) != 0` | Enters LSASS-oriented branch. |
| Rule data at `param_3 + 0x1a` | Used for LSASS ASR evaluation. |
| `ResolveAsrActionOverride` | Can refine action value to `1` or `6`. |
| General ASR action path | `EmitAsrNotification(param_3 + 0x1a, action, 7, ...)`. |

LSASS message:

```text
Friendly process '%ls' was blocked by ASR lsass  rule, target=%ls, commandline=%ls
```

#### Extra Alias Expansion / Tracking

| Gate | Effect |
|---|---|
| `DAT_1810adf50 != 0` (`MpDisableBmEnvVarOptimization`) | The code uses image-name resolver logic to enumerate additional names and emit extra `0x402b`/`0x402c` events. |
| Event id still `0x402b`, flag `0x20` present, and process flag `+0x7b1` set | Calls `LookupTrackedProcessContextByPidVersion` and `MarkProcessEligibleForHollowingCheck(..., 1)` to update tracked process state. |

### Type `2`: Cleanup / Deferred Processing

| Check | Effect |
|---|---|
| `ShouldUpdateDeferredProcessState(process_ctx)` true | Calls `UpdateDeferredProcessPathState`, which updates deferred path/process state if `process_ctx + 0xa10` exists. |
| Always | Calls `ProcessScanCleanupChecks(..., 2)`. |
| Cleanup type `2` | Clears flags `+0x799`, `+0x7b4`, `+0x7b2`, `+0x7b0`; closes cached token/process handle at `+0x7a8`. |

### Type `4`: Cleanup Only

Calls `ProcessScanCleanupChecks(..., 4)` and returns.

### Type `0x2d`: Code-Signing Verdict Report, Event `0x40a5`

| Check | Effect |
|---|---|
| Byte at `param_3[0x18].Blink` must be nonzero | If not set, returns error `-0x7ff8ffce`. |
| Resolves path from `param_3[0xe]` | Uses inline or heap string. |
| Pulls signer/cdhash/teamid strings | From `param_3 + 0x12`, `+0x14`, `+0x16`. |
| Formats verdict string | Uses `FormatAnsiStringAlloc`. |
| Reports | `EmitBehaviorModuleEvent` with event id `0x40a5`. |

Format string:

```text
verdict:%d;codesigningflags:%u,signer:%s,cdhash:%s,teamid:%s
```

## Other Registered Callback Handlers

`InvokeModuleScanCallbacks` iterates registered callback objects. The callback chain visible around the stack has several alternate handlers besides `ClassifyImageModuleEvent`.

| Handler | Address | Key behavior |
|---|---:|---|
| `ModuleTrustEvaluationCall` | `0x180125ae0` | Runs predicate at callback vtable slot `0x18`, then dispatches to handler at slot `0x70`. Known targets include `ClassifyImageModuleEvent` and `Type4ModulePathCallback`. |
| `Type4ModulePathCallback` / `HandleType4ModulePathNotification` | `0x1804d05c0` / `0x1804d0610` | Handles notification type `4`; checks path, calls lower-level rule/metastore helpers, and may update metastore. |
| `SecondaryBehaviorCallbackRouter` | `0x180125d20` | Runs callback predicate then dispatches slot `0x68` to `RunSecondaryBehaviorCallback`, `ClassifyFileBehaviorNotification`, `ProcessFileRuleActionCallback`, or indirect. |
| `ClassifyFileBehaviorNotification` | `0x180b02cc0` | Large event mapper for types `7`, `8`, `9`, `0xb`, `0xc`, `0xd`, `0xe`, `0xf`, `0x10`, `0x11`, `0x27`, `0x28`, `0x2e`. Emits event IDs such as `0x4002`, `0x4004`, `0x4032`, `0x4038`, `0x4039`, `0x4048`, `0x408d`, `0x40af`. Has excluded-file skip through `IsPathInExcludedFileCache` when `DAT_1810adf19` is enabled. |
| `ProcessFileRuleActionCallback` | `0x1804d3880` | Handles file/process notification types around `0xb`, `0x11` depending on `DAT_1810adf0c`. Checks path rule state and may mark/report an action through process callbacks. |
| `GenericBehaviorEventCallback` / `MapGenericBehaviorEventToModuleReport` | `0x1805dd320` / `0x1805dd3c0` | Generic behavior event mapper. Maps many type values to strings/events such as `AR`, `EMS`, `TELEMETRY`, `BM_STARTUP`, `INTEGRITY`, `RTP`, `BM_FILEOPEN`, `FOLDERGUARD`, `CmdLowfi`, etc. Some event types are forwarded indirectly. |

This means `ClassifyImageModuleEvent` is not the only registered consumer of the notification, but it is the one that contains the module trust/hollowing-related path in this trace.

## Memory Scan Linkage

The hollowing check above is a memory-region property check, but the broader process memory scan path appears in a separate function: `StartProcessMemoryScan`.

Important strings:

```text
EMS scan for process: %ls pid: %lu, sigseq: 0x%llX, sendMemoryScanReport: %d, source: %lu
targeted memory scan for process: %ls pid: %lu, sigseq: 0x%llX, sendMemoryScanReport: %d, source: %lu
skipping EMS scan for process: %ls pid: %u, sigseq: 0x%llX due to process exclusion
```

### `StartProcessMemoryScan`: EMS / Targeted Memory Scan Setup

| Step | Check / behavior | Effect |
|---|---|---|
| Resolve process image/name | `ResolveProcessImageNameByPidVersion(process_id/version)` | Uses metastore if available; otherwise opens process with access `0x100000` and queries image name. |
| Exclusion check | `IsProcessExcludedFromMemoryScan(name)` checks path/policy exclusion flags. | Skips EMS scan due to process exclusion. |
| Select scan mode | If `ctx + 0x50 == 0`, logs `EMS scan`; otherwise logs `targeted memory scan`. | Targeted scan has base/size. |
| Build scan object | Allocates `0x210` bytes and initializes through `InitializeProcessMemoryScanContext`. | Creates process memory scan context. |
| Targeted range | If `ctx + 0x50 != 0`, aligns base down to page boundary and length up to page boundary, capped at `0x2000000`. | Stores range in scan object at `+0x1b8` and `+0x1dc`. |
| Scan start | `BeginProcessMemoryScanOnce` then `ExecuteProcessMemoryScan(scan_ctx, 2)`. | Starts/executes memory scan. |
| Result handling | If result `6`, maps to action value `4`; if result `7`, maps to action value `2`; otherwise default `1`. | Calls callback at `ctx + 0x38` with name such as `pid:%lu` or `%ls:%lu`. |

Related callers:

| Caller | Behavior |
|---|---|
| `RunEmsProcessMemoryScan` | Builds EMS context and scans a list of candidate PIDs or all snapshot processes. Opens each process with `OpenProcess(0x410)` and validates creation time before scanning. |
| `EnumerateProcessesAndRunMemoryScan` | Enumerates processes using `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`; optionally filters by process name substrings; opens each with `OpenProcess(0x410)`, validates creation time, and calls `StartProcessMemoryScan`. |

This memory scan path is distinct from `CheckProcessHollowing`, but the two can complement each other: the dispatcher and taint paths can mark/reinspect a process, while EMS/targeted scan setup performs memory scanning on selected processes or ranges.

## Skip / Whitelist / Cache Overview

| Mechanism | Function / flag | What it skips or changes |
|---|---|---|
| PID creation-time validation | `AcquireProcessHandleForScan` | Prevents scanning/reporting the wrong process after PID reuse. |
| Disable process hollowing checks | `MpDisableProcessHollowingChecks` / `DAT_1810ade21` | Skips `CheckProcessHollowing`. |
| Hollowing already reported | `process_ctx + 0x7b2` | Skips repeated `Hollow1`. |
| Disable SeDebug checks | `MpDisableSeDebugChecks` / `DAT_1810ade22` | Skips SeDebug EoP check. |
| SeDebug already reported | `process_ctx + 0x7b4` | Skips repeated SeDebug report. |
| Excluded-file cache | `IsPathInExcludedFileCache` | Treats file/path as excluded/known; can skip reporting or affect trust. |
| Disable processing excluded notifications | `MpDisableBmProcessingExcludedFileNotifications` / `DAT_1810adf19` | In several handlers, excluded files skip main processing. |
| Disable trusting excluded files | `MpDisableTrustingExcludedFiles` / `DAT_1810adec9` | Prevents exclusion status from automatically making final trust decision true. |
| Friendly cache | `DAT_18107f928` / `DAT_18107f930` | Reuses previous friendly result by hashed key. |
| Friendly cache key mode | `MpUseNewFriendlyCacheKey` | Chooses between path-only hash and formatted key `path + flags`. |
| Disable friendly slow check | `MpDisableFriendlySlowCheck` | Can suppress slow fallback friendly check. |
| Directory slow-check policies | `MpDisableDllFriendlySlowCheckWinDir`, `MpDisableDllFriendlySlowCheckProgramDir`, `MpDisableDllFriendlySlowCheckAllDirs`, `MpOnlyCfaDllFriendlySlowCheckAllDirs` | Adjust slow friendly check eligibility. |
| Disable hardlink check | `MpDisableHardlinkCheck` / `DAT_1810ade62` | Switches from alternate-name expansion to direct reporting. |
| EMS process exclusion | `IsProcessExcludedFromMemoryScan` | Skips EMS scan if process name/path has exclusion flags. |

## Detection / Action Overview

| Detection / action | Trigger | Function path |
|---|---|---|
| `Hollow1` | Executable region in expected image span is not `MEM_IMAGE`. | `ProcessScanCleanupChecks` -> `CheckProcessHollowing` -> `ReportInternalProcessAnomaly`. |
| Integrity / EoP internal detection | Current integrity-like value exceeds stored baseline. | `ProcessScanCleanupChecks` -> `CheckProcessIntegrityElevation` -> `ReportInternalProcessAnomaly`. |
| `SeDebugEop` / `SeDebugEop1` | `SeDebugPrivilege` token state changes from baseline. | `ProcessScanCleanupChecks` -> `CheckSeDebugPrivilegeEscalation` -> `ReportInternalProcessAnomaly`. |
| Module not trusted / not friendly | Type `5` final trusted decision false, no scan error, not suppressed by exclusion rules. | `ClassifyImageModuleEvent` type `5` -> `MarkProcessTaintedAndNotify` -> `Bm_ReinspectTrackedProcess`. |
| ASR Office Block Injection | Type `6`, Office ASR rule branch conditions met. | `ClassifyImageModuleEvent` type `6` -> formatted Office message / `EmitAsrNotification`. |
| ASR LSASS rule | Type `6`, LSASS branch conditions met. | `ClassifyImageModuleEvent` type `6` -> LSASS message / `EmitAsrNotification`. |
| EMS / targeted memory scan | Separate EMS context selects process or range, not excluded. | `RunEmsProcessMemoryScan` / `EnumerateProcessesAndRunMemoryScan` -> `StartProcessMemoryScan`. |

## Notes For Reading The Trace

- The supplied `OpenProcess` moment sits inside `AcquireProcessHandleForScan`, called from `CheckProcessHollowing` in this stack.
- The immediate memory-region logic in this stack is not a generic full address-space scan. It validates the image allocation span with `VirtualQueryEx` and checks for executable pages that are not `MEM_IMAGE`.
- The broader module trust path can trigger process taint and reinspection when a module load is neither friendly nor excluded/trusted.
- The broader EMS/targeted memory scan implementation exists nearby but is not the same function as `CheckProcessHollowing`; it has explicit process-exclusion skip logic and targeted range support.
- Several decisions are cache-backed: metastore path cache, excluded-file cache, friendly cache, and alternate-name/hardlink expansion. These caches affect whether Defender repeats expensive work, but the core gates above are the main behavior decisions in this trace.
