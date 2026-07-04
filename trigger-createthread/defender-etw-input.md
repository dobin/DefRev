# Defender BM ETW Architecture Notes

## Scope

This report summarizes the high-level data model and event pipeline visible in the analyzed Defender binary. The focus is ETW consumption and conversion into internal Behavior Monitoring (`BM_*`) events, especially process, module, thread, and API-call related events.

The provider names `Microsoft-Windows-Threat-Intelligence`, `Microsoft-Windows-Kernel-Process`, and `Microsoft-Windows-Kernel-Audit-API-Calls` were not present as plain strings in this image. The binary instead opens real-time Defender logger sessions and classifies incoming ETW records by provider GUID constants. The provider GUID constants are compared in code, but Ghidra did not name them.

## Main Pipeline

1. `BmController` initializes the Behavior Monitoring subsystem.
2. `EtwControllerImpl` opens three ETW real-time logger sessions: `DefenderApiLogger`, `DefenderAuditLogger`, and `DefenderApiLoggerLowPriv`.
3. The ETW callback (`FUN_180129840`) forwards each raw record into the BM metastore ETW sink.
4. The main ETW dispatcher (`FUN_1805d71bc`) filters self-generated or disabled events, classifies provider GUIDs, maps provider event IDs into internal BM event IDs, extracts properties through TDH, and calls event-family-specific converters.
5. Converter functions emit BM notifications/behavior events through `FUN_18018689c` and `FUN_18003d798`, or directly through `EmitBehaviorModuleEvent` for module/report style events.
6. BM notifications are queued into per-process `ProcessContext` objects, replayed in timestamp order, enriched with process/module metadata, and persisted/evaluated through `Bm_MetaStore*`.

Important observed functions:

- `FUN_18086e2fc`: `BmController` constructor/initializer; calls ETW controller setup when BM ETW is enabled.
- `FUN_180b0c194`: `EtwControllerImpl` constructor; opens Defender logger sessions.
- `FUN_180754064` / `FUN_1806be7c4`: dynamic loader for `OpenTraceW`, `ProcessTrace`, `CloseTrace`, and TDH APIs.
- `FUN_180129840`: ETW callback wrapper that forwards records to metastore ETW processing.
- `FUN_1805d71bc`: main ETW record classifier/dispatcher.
- `FUN_1805ba57c`: provider GUID classifier.
- `FUN_18057071c`: provider event ID to internal ETW event index mapper.
- `FUN_18018689c` / `FUN_18003d798`: create and enqueue internal `EtwEvent`/BM behavior notifications.
- `GetBehaviorEventName`: maps BM behavior IDs to human-readable names.
- `GetNotificationTagName`: maps notification tags such as `ProcessStart`, `ModuleLoad`, `RemoteThreadCreate`, and `EtwEvent`.

## Global Configuration State

### BM ETW Settings Block

Purpose: global feature gates and sizing/bitmap controls for BM and ETW processing.

Loaded by `FUN_180b014d0`; defaults registered by `FUN_18054fcc8`.

Key fields/settings:

- `DAT_1810adda3`: `MpDisableBmEtw`.
- `DAT_1810adda4`: `MpDisableBmEtwProcessing`.
- `DAT_1810add80`: `MpBmEtwEventList`, bitmap for internal ETW event indexes 0..63.
- `DAT_1810add88`: `MpBmEtwEventList2`, bitmap for internal ETW event indexes above 63.
- `DAT_1810adec0`: `MpBmEtwAllocVmMinimumSize`.
- `DAT_1810adf20`: `MpBmEtwFormatterType`.
- `DAT_1810adf39`: `MpDisableBmEtwAggregation`.
- `DAT_1810adf40`: `MpBmEtwAggregationInterval`.

Interactions:

- `EtwControllerImpl` copies the event-list bitmaps into an enabled-event array.
- `FUN_1805d71bc` increments per-event counters and drops disabled internal event indexes before conversion.
- `BmController` skips ETW controller initialization when `MpDisableBmEtw` is set.
- `FUN_1805d71bc` returns early when `MpDisableBmEtwProcessing` is set.

## Primary Structures

### `BmController`

Purpose: root object for Behavior Monitoring. Owns queue controllers, process context state, module scanning/report callbacks, ETW controller integration, and metastore interactions.

Key fields observed:

- vtable: `BmController::vftable`.
- Multiple synchronization primitives / critical sections.
- Queue/controller references used by `QueueRtpNotification`, `QueueBmNotification`, and process context setup.
- ETW controller sub-object or pointer initialized from `FUN_18068d120` when ETW support is enabled.
- Module callback/router state used by `ModuleCallbackRouter`, `AnalyzeImageLoadEvent`, and `EmitBehaviorModuleEvent`.
- Deduplication/throttle state derived from `MpTelemetryDedupTimeout` and `MpTelemetryDedupMaxSize`.

Interactions:

- Holds or reaches `EtwControllerImpl`.
- Holds the process-context map/queue controller used by `SubmitNotificationToProcessContext`.
- Calls into `Bm_MetaStore` for counters, verdicts, process info, and reporting.
- Routes module notifications to module analysis callbacks and eventually to BM behavior reports.

### `EtwControllerImpl`

Purpose: owns real-time ETW trace subscriptions and per-ETW-event dispatch state.

Constructed in `FUN_180b0c194`.

Key fields observed:

- vtable: `EtwControllerImpl::vftable`.
- current process ID, used to ignore Defender's own emitted events.
- trace handles for:
  - `DefenderApiLogger`
  - `DefenderAuditLogger`
  - `DefenderApiLoggerLowPriv`
- three `EtwFormatter` subobjects, one per trace/logger.
- event count arrays for internal ETW indexes.
- enabled-event bitmap/array derived from `MpBmEtwEventList` and `MpBmEtwEventList2`.
- minimum allocation threshold from `MpBmEtwAllocVmMinimumSize`.
- reference to an owning/controller object passed in during construction.

Interactions:

- Calls `OpenTraceW` with callback `FUN_180129840` for each real-time session.
- Uses `EtwFormatter` instances to decode ETW records through TDH.
- Hands raw records to the metastore ETW sink (`Bm_GetMetaStore` then object at metastore offset `+0x90`).

### `EtwFormatter`

Purpose: runtime wrapper for ETW and TDH APIs plus scratch buffers used to decode event properties.

Constructed by `FUN_1806be758`; initialized by `FUN_1806be7c4` or `FUN_180754064`.

Key fields observed:

- vtable: `EtwFormatter::vftable`.
- module handle for `Sechost.dll`.
- module handle for `Tdh.dll`.
- function pointers:
  - `OpenTraceW`
  - `ProcessTrace`
  - `CloseTrace`
  - `TdhGetEventInformation`
  - `TdhGetPropertySize`
  - `TdhGetProperty`
  - `TdhFormatProperty`
- scratch string/value buffers initialized by `FUN_1806be918`.

Interactions:

- Used by `EtwControllerImpl` when opening sessions and decoding records.
- `FUN_1805a08b4` uses TDH-style calls to retrieve `TRACE_EVENT_INFO` for a raw ETW record.
- Converter helpers (`FUN_18018cb90`, `FUN_18018be9c`, `FUN_18018c444`) read individual decoded properties from event records using this formatter state.

### Raw ETW Record / `EVENT_RECORD`-like Object

Purpose: raw event passed to the ETW callback.

Key fields used by the BM dispatcher:

- provider GUID at the standard `EVENT_HEADER.ProviderId` location, classified by `FUN_1805ba57c`.
- event descriptor ID used by `FUN_18057071c` and family-specific converters.
- process ID used to skip events generated by Defender itself.
- flags used to skip generated/unsupported event records.
- user context pointer used to reach the relevant formatter/controller state.

Interactions:

- Passed from `OpenTraceW` callback `FUN_180129840` into `FUN_1805d71bc`.
- Decoded through TDH into `TRACE_EVENT_INFO` and property values.
- Converted into internal BM events through family-specific converter functions.

### `TRACE_EVENT_INFO` / Decoded ETW Schema Object

Purpose: TDH-decoded schema and metadata for one ETW event type.

Key fields observed:

- event/task/opcode metadata used by converter dispatch.
- top-level property count / property descriptors.
- provider/task names used in some diagnostics or special cases.

Interactions:

- Allocated by `FUN_1805a08b4` after probing size through TDH.
- Read by converters to extract properties by ordinal.
- Destroyed after the converter completes.

### `EtwDataItem`

Purpose: name/value representation for decoded ETW properties. RTTI references show `std::vector<std::unique_ptr<EtwDataItem>>` as the common callback payload shape.

Key fields inferred:

- property name.
- formatted value.
- value/type metadata.

Interactions:

- Converter callback type signatures accept vectors of `EtwDataItem`.
- Generic ETW-to-BM behavior conversion can forward arbitrary decoded properties as extra BM fields.

### `PersistentProcessID`

Purpose: stable process identity composed from PID and creation time/version.

Key fields observed:

- process ID.
- process creation time / PID version.

Interactions:

- Used as the key in the process context map.
- Used by `Bm_MetaStoreLookupVerdict` to avoid reporting excluded/trusted target processes.
- Used in remote-thread, open-process, process-start, and module-load reporting to disambiguate PID reuse.

### `ProcessContext`

Purpose: per-process state object used by BM to sequence notifications, maintain process metadata, and attach process identity to behavior events.

Key fields observed:

- persistent process identity around offsets `+0x198` / `+0x1a0`.
- process image path and resolved DOS path cache.
- notification priority heap/vector at offsets around `+0x48` / `+0x50`.
- queue lock around `+0x80`.
- token/process handle cache for protected/elevated process checks.
- deferred process start notification at `+0xa20`.
- deferred process termination notification at `+0xa28`.
- deferred internal/module notification vector around `+0xa30`..`+0xa40`.
- per-notification counters around `+0x5b0`.
- flags controlling exclusion, stopped state, termination state, and initialization state.

Interactions:

- `SubmitNotificationToProcessContext` locates the correct `ProcessContext` by `PersistentProcessID`.
- `ProcessContextPushNotification` inserts notifications into a per-process ordered heap and schedules a worker item.
- `ProcessScanQueue` pops notifications, initializes missing process metadata, replays deferred module notifications, and calls `AnalyzeImageLoadEvent`.
- `InitializeProcessContextAndReplayDeferredNotifications` opens process tokens, resolves image paths, initializes module trackers, and replays deferred notifications.

### Process Context Map / Queue Controller

Purpose: global index and dispatch layer that maps notifications to process contexts.

Key fields observed:

- critical section around offset `+0x38`.
- hash table/sentinel nodes around offsets `+0x68`, `+0x78`, `+0x90`.
- process context factory at `param_1 + 0x70` in `QueueRtpNotification`.
- async worker submission path to a global pool.

Interactions:

- `QueueRtpNotification` converts raw RTP/FDR notifications into internal notification objects through a notification factory.
- `QueueBmNotification` sends already-created BM notification objects into the same process-context routing path.
- `SubmitNotificationToProcessContext` looks up or rejects the target process context.
- Missing process contexts cause drops or lazy creation depending on notification type.

### Notification Object Hierarchy

Purpose: polymorphic internal BM notification model. These are not raw ETW records; they are normalized events queued to a `ProcessContext`.

Key fields/methods observed:

- virtual method returning notification tag, used by `GetNotificationTagName`.
- process identity getter.
- timestamp/sequence getter.
- inclusion/exclusion predicates.
- enrichment hook that receives process image path and identity.
- push/priority comparison methods used by `ProcessContextPushNotification`.

Important notification tags:

- `1`: `ProcessStart`
- `2`: `ProcessTerminate`
- `3`: `ProcessCreate`
- `5`: `ModuleLoad`
- `6`: `OpenProcess`
- `0x21`: `RemoteThreadCreate`
- `0x25`: `EngineInternal`
- `0x26`: `EtwEvent`
- `0x29`: `ProcessForkCount`
- `0x2a`: `MemoryMap`
- `0x2b`: `MemoryProtect`
- `0x2c`: `ProcessControl`

Interactions:

- Created by the notification factory called from `QueueRtpNotification`.
- Created directly from ETW converters by `FUN_18018689c` / `FUN_18003d798`.
- Routed into `ProcessContext`, then analyzed or reported by module/behavior callbacks.

### BM Behavior Event Descriptor

Purpose: compact internal event payload that represents one `BM_*` behavior.

Key fields observed:

- behavior ID, such as `0x401f` for `BM_Etw_OpenProcess`.
- primary string payload, usually image path, target name, or event-specific string.
- secondary string/payload, often target process, access rights, injection type, or structured JSON.
- optional decoded ETW property list.
- flags such as `0x400000` used by module/event emission.
- source/sequence/timestamp fields copied from the originating notification.

Interactions:

- Created by ETW converters via `FUN_18018689c`.
- Converted into an internal notification by `FUN_18003d798`.
- Emitted to module/report pipeline by `EmitBehaviorModuleEvent`.
- Named by `GetBehaviorEventName`.

### `Bm_MetaStore`

Purpose: persistent and in-memory BM state store. It tracks process identities, verdicts, counters, telemetry, and event records.

Key fields observed:

- ETW sink/processor object at metastore offset `+0x90`, used by `FUN_180129840`.
- process identity / verdict stores used by `Bm_MetaStoreLookupVerdict`.
- counters for dropped/deferred/missing events around offsets such as `+0x370`..`+0x380`.
- process info and detection/event persistence functions (`Bm_MetaStoreRecordEvent`, `Bm_MetaStoreLookupVerdict`).

Interactions:

- ETW callback obtains it through `Bm_GetMetaStore` and invokes the ETW processor.
- Remote-thread, module-load, and process-control paths query verdicts to suppress excluded/trusted processes.
- `ProcessContextPushNotification` removes process identity state on process termination.
- `EmitBehaviorModuleEvent` may enqueue AI/detection processing through metastore state.

## ETW Provider Classification

`FUN_1805ba57c` classifies incoming ETW records by comparing `EVENT_RECORD.EventHeader.ProviderId` against a static GUID table. The function returns small provider-family IDs (`1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, etc.). The analyzed image does not label those GUIDs with provider names.

`FUN_18057071c` then maps `(provider-family, event-id)` into an internal event index. That index is checked against `MpBmEtwEventList` / `MpBmEtwEventList2`. Only enabled indexes proceed to conversion.

High-value families for process/API behavior:

- Family `1`: API/process manipulation events such as `PsSetLoadImageNotifyRoutine`, `TerminateProcess`, `SetThreadContext`, `WriteMemory`, `OpenProcess`, `OpenThread`, and shutdown registration.
- Family `2`: process/thread style events, including event IDs `1000`, `1001`, `1002`, `1003`, and remote-thread-related IDs `0x1cb`, `0x1cc`, `0x1cf`.
- Family `4`: Threat-Intelligence-like process/thread/memory/driver events, including `SuspendThread`, `ResumeThread`, `SuspendProcess`, `ResumeProcess`, `LoadDriver`, `UnloadDriver`, `LoadDevice`, `UnloadDevice`, and some memory/protection events.
- Family `8`: audit/security style events, including logon, scheduled task, account/password, and related audit events.
- Family `0xf`: clipboard aggregate event path.

Because provider names are absent, the likely mapping to the providers of interest is architectural rather than string-confirmed: process/memory/thread operations align with `Microsoft-Windows-Threat-Intelligence`; process lifecycle and remote thread events align with kernel process instrumentation; logon/task/account events align with audit provider streams.

## ETW-To-BM Conversion Paths

### Generic ETW Event Creation

The shared creation path is:

1. Family-specific converter extracts relevant ETW properties through helper calls such as `FUN_18018cb90`, `FUN_18018be9c`, or `FUN_18018c444`.
2. Converter calls `FUN_18018689c(EtwControllerImpl, bm_event_id, primary, secondary, extra_data, flags, identity)`.
3. `FUN_18018689c` increments ETW event counters and calls `FUN_18003d798`.
4. `FUN_18003d798` constructs an internal notification with tag `EtwEvent` and submits it into the BM notification path.
5. The notification is routed through `QueueBmNotification` / `SubmitNotificationToProcessContext` / `ProcessContextPushNotification`.

### Open Process / Open Thread / Terminate / Memory Manipulation

Relevant functions:

- `FUN_1803a6650`: top-level family-1 dispatcher.
- `FUN_1803a7d54`: emits `BM_Etw_TerminateProcess` (`0x4019`).
- `FUN_1803a64b0`: emits `BM_Etw_SetThreadContext` (`0x401d`).
- `FUN_1807b5bf0`: emits `BM_Etw_OpenProcess` (`0x401f`).
- `FUN_18073c1c4`: emits `BM_Etw_OpenThread` (`0x4020`).
- Other family-1 branches emit `BM_Etw_PsSetLoadImageNotifyRoutine`, `BM_Etw_WriteMemory`, `BM_Etw_RegisterLastShutdown`, and `BM_Etw_RegisterShutdown`.

Typical extracted fields:

- source/target image name.
- access rights.
- thread ID.
- API result/status.
- callback address for image notify registration.

Design note: these are normalized as `BM_Etw_*` behavior events, not as raw ETW records. The converter strips event-provider-specific property layout and emits a small common behavior payload.

### Process Create / Process Start / Process Terminate

Process lifecycle is primarily represented by BM notification tags and behavior IDs:

- notification tag `ProcessCreate` (`3`).
- notification tag `ProcessStart` (`1`).
- notification tag `ProcessTerminate` (`2`).
- behavior `BM_ProcessCreate` (`0x4010`).
- behavior `BM_ProcessStart` (`0x4011`).

Observed flow:

- Raw process notifications are converted by the notification factory in `QueueRtpNotification`.
- `SubmitNotificationToProcessContext` resolves the target `ProcessContext` using `PersistentProcessID`.
- `ProcessContextPushNotification` handles process termination specially by marking termination time and removing process identity state from metastore.
- `ProcessScanQueue` treats `ProcessStart` specially: startup/module notifications may be deferred until process image path and token metadata are initialized.
- `InitializeProcessContextAndReplayDeferredNotifications` initializes process metadata and replays deferred module notifications.

The ETW dispatcher contains process-family handling, but the higher-level BM design treats process lifecycle as first-class `Notification` objects, then derives `BM_ProcessCreate` / `BM_ProcessStart` reports downstream.

### Module Load / Load Library

Relevant functions:

- `ProcessScanQueue`
- `InitializeProcessContextAndReplayDeferredNotifications`
- `AnalyzeImageLoadEvent`
- `CaptureStartupModuleMetadataForProcess`
- `InvokeModuleScanCallbacks`
- `ModuleCallbackRouter`
- `GenericBehaviorEventCallback`
- `MapGenericBehaviorEventToModuleReport`
- `EmitBehaviorModuleEvent`

Observed flow:

1. Module-load notifications are queued against a process context.
2. If the process context is not fully initialized, module notifications are deferred.
3. `InitializeProcessContextAndReplayDeferredNotifications` resolves image path, token/process state, and module tracker state.
4. `AnalyzeImageLoadEvent` marks module-processing state, captures startup module metadata for process start/create/fork events, and invokes module scan callbacks.
5. `ModuleCallbackRouter` selects specialized module trust, secondary behavior, or generic behavior callback paths.
6. `MapGenericBehaviorEventToModuleReport` maps generic event categories into BM behavior IDs.
7. `EmitBehaviorModuleEvent` emits the final module/behavior report and optionally records it through metastore/AI/detection logic.

Primary BM event:

- `BM_ModuleLoad` (`0x4014`).

Related report fields from strings/XML emitters:

- process ID and process creation time.
- image path and short image name.
- excluded/friendly flags.
- sequence ID and notification timestamp.

### Remote Thread Create / Code Injection

Relevant functions:

- `ReportRemoteThreadInjectionBehavior`
- `EmitRemoteThreadCreateXmlReport`
- `GetRemoteThreadTargetImagePath`
- `FUN_180187dc8`: ETW family converter for suspend/resume/thread-style event variants.

Observed flow:

1. A `RemoteThreadCreate` notification (`0x21`) contains target process identity, target thread identity, target image path, and timestamp/sequence metadata.
2. `EmitRemoteThreadCreateXmlReport` formats the XML/report fields for `RemoteThreadCreate`.
3. `ReportRemoteThreadInjectionBehavior` checks metastore verdicts for the target process and suppresses excluded/trusted targets.
4. It emits multiple BM behaviors:
   - `BM_RemoteThreadCreate` (`0x400e`)
   - `BM_Etw_CodeInjection` (`0x402e`) with `remotethread` marker
   - `BM_Etw_V2CodeInjection` (`0x408a`) with `injectiontype:remotethread` and target image/PPID details

Key fields:

- target process ID.
- target process creation time.
- target thread ID.
- target thread creation time.
- target image name and short image name.
- target parent process identity where available.

Design note: remote thread creation is treated both as a direct process/thread notification and as a higher-level code injection behavior.

### Driver / Kernel Callback / Load Image Notify

Relevant functions:

- `FUN_1803a6728`: emits `BM_Etw_PsSetLoadImageNotifyRoutine` (`0x4018`).
- `FUN_1807fd694`: emits driver-related events such as `BM_Etw_LoadDriver`, `BM_Etw_UnloadDriver`, `BM_Etw_LoadDevice`, `BM_Etw_UnloadDevice`.

Key fields:

- callback address.
- API result.
- driver path.
- driver name.

Interactions:

- Driver/kernel callback events are created as `BM_Etw_*` behavior events and routed through the same `EtwEvent` notification path.

### Audit / Account / Scheduled Task Events

Relevant function:

- `FUN_180620a28`

BM events emitted include:

- `BM_Etw_LogonSuccess` (`0x4064`)
- `BM_Etw_LogonFailure` (`0x4065`)
- `BM_Etw_ScheduledTaskCreate` (`0x4062`)
- `BM_Etw_ScheduledTaskUpdate` (`0x4063`)
- `BM_Etw_AccountPasswordChanged` (`0x4067`)
- `BM_Etw_AccountPasswordReset` (`0x4068`)
- other account/user/security events listed by `GetBehaviorEventName`.

Interactions:

- These events are normalized into the same generic `EtwEvent` notification path, but are less tightly coupled to `ProcessContext` than module/process/thread events.

## Internal BM Event ID Map Of Interest

Selected IDs from `GetBehaviorEventName`:

- `0x400e`: `BM_RemoteThreadCreate`
- `0x4010`: `BM_ProcessCreate`
- `0x4011`: `BM_ProcessStart`
- `0x4014`: `BM_ModuleLoad`
- `0x4018`: `BM_Etw_PsSetLoadImageNotifyRoutine`
- `0x4019`: `BM_Etw_TerminateProcess`
- `0x401d`: `BM_Etw_SetThreadContext`
- `0x401e`: `BM_Etw_WriteMemory`
- `0x401f`: `BM_Etw_OpenProcess`
- `0x4020`: `BM_Etw_OpenThread`
- `0x402e`: `BM_Etw_CodeInjection`
- `0x4033`: `BM_Etw_AllocVmLocal`
- `0x4070`: `BM_Etw_SuspendThread`
- `0x4071`: `BM_Etw_ResumeThread`
- `0x4072`: `BM_Etw_SuspendProcess`
- `0x4073`: `BM_Etw_ResumeProcess`
- `0x4074`: `BM_Etw_LoadDriver`
- `0x4075`: `BM_Etw_UnloadDriver`
- `0x4076`: `BM_Etw_LoadDevice`
- `0x4077`: `BM_Etw_UnloadDevice`
- `0x4079`: `BM_Etw_ProtectVmLocal`
- `0x4089`: `BM_Etw_ReadVmRemote`
- `0x408a`: `BM_Etw_V2CodeInjection`
- `0x408b`: `BM_Etw_MapViewLocal`
- `0x4093`: `BM_Etw_DangerousSyscall`
- `0x4094`: `BM_Etw_CLRModuleLoad`
- `0x4095`: `BM_Etw_CLRAssemblyLoad`
- `0x4097`: `BM_Etw_ReadVmRemoteAgg`
- `0x4098`: `BM_Etw_WMICreateProcess`
- `0x40a0`: `BM_Etw_AmsiInitFailed`

## Design Interpretation

The Defender BM architecture is not a simple ETW logger. It is a normalization and enrichment system:

- Raw ETW records are consumed from Defender-owned real-time logger sessions.
- Provider-specific event schemas are hidden behind family converters.
- Provider event IDs are converted into stable internal BM event IDs.
- Process identity is normalized as `PersistentProcessID` to avoid PID reuse issues.
- Process, module, and thread events are routed through per-process queues so context exists before reports are emitted.
- Metastore verdicts suppress trusted/excluded targets and retain process/event state.
- Higher-level behaviors can be synthesized from lower-level events, as seen with remote thread create becoming both `BM_RemoteThreadCreate` and `BM_Etw_CodeInjection`/`BM_Etw_V2CodeInjection`.

For the providers of interest, the important architectural point is that Defender appears to consume their data indirectly through Defender logger sessions (`DefenderApiLogger`, `DefenderAuditLogger`, `DefenderApiLoggerLowPriv`) and then maps GUID/event IDs to BM behavior events. The conversion boundary is `FUN_1805d71bc` plus the family-specific converters; the process-context/module/report boundary is `QueueBmNotification` / `SubmitNotificationToProcessContext` / `ProcessScanQueue` / `EmitBehaviorModuleEvent`.