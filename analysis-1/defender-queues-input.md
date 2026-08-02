# Defender Queue Input Boundary Overview

This document focuses on the functions that sit before `ProcessContextPushNotification`: the places where an external or upstream signal is converted into an internal Defender/BM notification and routed toward the per-process queue.

## Summary

`ProcessContextPushNotification` is the final per-process enqueue point. It is not the original event generator.

The real input boundary is usually:

```text
RSIG/RTP command or BM/ETW event adapter
  -> QueueRtpNotification / QueueExtendedRtpNotification
  -> NotificationFactory
  -> QueueBmNotification
  -> SubmitNotificationToProcessContext
  -> ProcessContextPushNotification
```

Some events are internally re-emitted or propagated after Defender has already processed another event.

## Input Boundary Functions

| Function | Boundary Type | Description / Purpose | Event Types It May Emit |
|---|---|---|---|
| `FUN_180122690` | External RTP/RSIG adapter | Handles domain `1` notifications. Validates the notification domain and forwards valid input to the main RTP notification path. | Basic RTP/BM notifications, especially early process or file-related events accepted by `RSIG_RTP_NOTIFYCHANGE`. |
| `FUN_180123120` | External RTP/RSIG adapter with side callbacks | Handles domain `2` notifications. Runs extra registered callbacks before forwarding to the RTP queue path. This domain carries richer process-context data than domain `1`. | Process lifecycle style events, including termination/deferred process notifications and process-context updates. |
| `FUN_1806163d0` | External RTP/RSIG adapter | Handles domain `8` notifications. Validates the domain and forwards to the same RTP notification callback path. | Another RTP notification family. The exact semantic category is vtable/data-driven, but it feeds the same BM queue path. |
| `FUN_1805eeab0` | External RTP/RSIG adapter | Handles domain `9` notifications. Validates the domain and forwards to the same RTP notification callback path. | Another RTP notification family. Likely a special/priority notification domain because the global threadpool also has a type `9` work bucket. |
| `FUN_1801239f0` | RTP callback trampoline | Thin wrapper that calls the actual BM/RTP notify-change implementation. Used as a registered callback target by several domain adapters. | Forwards domain `1`, `2`, `8`, and `9` notifications toward `QueueRtpNotification`. |
| `QueueRtpNotification` | Main notification creation boundary | Takes the incoming RTP notification payload, calls the notification factory, creates one or more internal notification objects, then routes each one into `QueueBmNotification`. | Classic BM notifications such as process start, process create, module load, file open/change/create/delete, registry activity, network activity, remote thread creation, open process, memory-related BM events, and signing reports. |
| `QueueExtendedRtpNotification` | Extended notification creation boundary | Alternate input path for extended RTP notifications. Similar to `QueueRtpNotification`, but the raw input layout differs. This corresponds to extended RSIG command support. | Extended RTP notifications, including `RSIG_RTP_NOTIFYCHANGE_EX`-style inputs and newer BM event types. |
| `FUN_180a6c4a0` | External extended RTP/RSIG adapter | Gets the BM metastore/controller and forwards extended event input to `QueueExtendedRtpNotification`. | Extended notification payloads from the `RSIG_RTP_NOTIFYCHANGE_EX` path. |
| `FUN_180afb430` | Extended RTP callback trampoline | Thin wrapper around `FUN_180a6c4a0`. Used as the registered callback entry for the extended path. | Same as `FUN_180a6c4a0`: extended RTP/BM notifications. |
| `NotificationFactory` / `FUN_180124570` | Internal notification object factory | Converts raw RTP/BM input into concrete internal `INotification` objects. Can return multiple notification objects for one raw input. | Internal notifications consumed by `ProcessScanQueue`: types `1`, `2`, `3`, `5`, `6`, `0x29`, `0x2d`, plus other BM behavior notifications handled by secondary callbacks. |
| `QueueBmNotification` | Queue controller | Applies performance exclusions, invokes the factory, creates missing process context when needed, and forwards each notification into its target process context. | Does not create a new event family itself; routes factory-created notifications to process contexts. |
| `SubmitNotificationToProcessContext` | Process-context routing | Finds the tracked process context matching the notification PID/version, attaches path/process metadata, then calls `ProcessContextPushNotification`. | Same notification object it received; this is routing/enrichment, not original generation. |
| `PropagateNotificationToRelatedProcesses` | Internal propagation source | Re-emits an existing notification into related process contexts when propagation rules match. | Follow-up notifications for related/child/parent processes, especially propagation-parent and taint-related events. |
| `BroadcastNotificationToActiveProcessContexts` | Internal broadcast source | Broadcasts an existing notification to multiple active process contexts. Used by propagation behavior reports. | Propagation events, parent/related-process notifications, and signature-triggered behavior propagation. |
| `HandlePropagationBehaviorReport` | Internal behavior-report handler | Reads behavior report fields such as `PropagationMatch` and `PropagationParent`; can emit behavior reports directly or broadcast a notification to active process contexts. | `BM_SignatureTrigger`, `PropagationMatch`, `PropagationParent`, and related behavior-correlation events. |

## External Versus Internal Producers

| Producer Class | Functions | Source | Notes |
|---|---|---|---|
| RSIG/RTP command input | `FUN_180122690`, `FUN_180123120`, `FUN_1806163d0`, `FUN_1805eeab0`, `FUN_1801239f0` | External engine/RTP command interface | These are closest to the normal external input boundary for classic RTP notifications. They are callback/adaptor functions, not static detections. |
| Extended RSIG/RTP input | `FUN_180a6c4a0`, `FUN_180afb430`, `QueueExtendedRtpNotification` | External extended command interface | Handles extended notify-change inputs such as `RSIG_RTP_NOTIFYCHANGE_EX`. |
| Notification factory | `NotificationFactory` / `FUN_180124570` | Internal conversion layer | Turns raw input into one or more internal notifications. This is where raw event payloads become Defender queue items. |
| BM/ETW event families | Routed through `QueueRtpNotification` / factory | ETW-derived or sensor-derived behavior events | The event name table includes many `BM_Etw_*` events, indicating some notifications originate from ETW/event-provider telemetry before becoming BM notifications. |
| Internal propagation | `PropagateNotificationToRelatedProcesses`, `BroadcastNotificationToActiveProcessContexts`, `HandlePropagationBehaviorReport` | Defender-internal re-emission | These do not originate from outside telemetry. They create follow-up queue entries based on prior Defender decisions or behavior correlations. |

## Event Families Seen In The Input Path

The event-name mapping function lists the BM event families that can be represented by internal notifications. The table below groups the most relevant families.

| Event Family | Example Event Names | Likely Source |
|---|---|---|
| Process lifecycle | `BM_ProcessCreate`, `BM_ProcessStart`, `BM_Etw_TerminateProcess` | RTP/process monitoring and ETW-derived process events. |
| Module/image load | `BM_ModuleLoad`, `BM_Etw_PsSetLoadImageNotifyRoutine`, `BM_Signer` | Image-load monitoring, module notifications, signing verdict input. |
| Process access / injection | `BM_OpenProcess`, `BM_BlockOpenProcess`, `BM_RemoteThreadCreate`, `BM_Etw_CodeInjection`, `BM_Etw_V2CodeInjection`, `BM_Etw_SetThreadContext`, `BM_Etw_WriteMemory`, `BM_Etw_ReadVmRemote`, `BM_Etw_MapViewLocal` | ETW-derived and behavior-monitor telemetry for injection and process-access activity. |
| Memory manipulation | `BM_MemoryMap`, `BM_MemoryProtect`, `BM_Etw_AllocVmLocal`, `BM_Etw_ProtectVmLocal` | Memory map/protect/allocation telemetry. |
| File activity | `BM_CreateFile`, `BM_ChangeFile`, `BM_RenameFile`, `BM_DeleteFile`, `BM_OpenFile`, `BM_FileMetaData`, `BM_FileSequentialRead`, `BM_HardLinkFile`, `BM_CopyFile` | File-system/RTP monitoring. |
| Registry activity | `BM_RegistryKeyCreate`, `BM_RegistrySetValue`, `BM_RegistryDeleteValue`, registry block/restore/replace variants | Registry monitoring and tamper/hardening sensors. |
| Network activity | `BM_NetworkConnect`, `BM_NetworkDataSend`, `BM_NetworkDetection`, `BM_Network_PortOpen`, `BM_Network_ConnectionOpen`, socket events | Network HIPS / network behavior telemetry. |
| Credential / identity access | `BM_Etw_CredReadCredentials`, `BM_Etw_CredEnumerate`, `BM_Etw_VaultFindCredentials`, `BM_Etw_LDAPSearch`, logon success/failure events | ETW-derived credential, vault, LDAP, and logon telemetry. |
| Service / driver / device activity | `BM_Etw_ServiceStarted`, `BM_Etw_ServiceChangeBinaryPath`, `BM_Etw_LoadDriver`, `BM_Etw_LoadDevice`, unload variants | ETW/service-control/device telemetry. |
| User/input/hooks | `BM_Etw_SetWindowsHook`, `BM_Etw_SetEventHook`, `BM_Etw_GetAsyncKeyState`, `BM_Etw_RegisterInputDevices` | ETW/user-input/hook-related telemetry. |
| ASR / exploit / policy | `BM_Etw_BlockExploit`, `BM_Etw_ExploitProtection`, `BM_Taint`, `BM_ProcessControl` | ASR/exploit protection and internal Defender policy decisions. |
| Internal/signature propagation | `BM_SignatureTrigger`, `BM_Parent`, `PropagationMatch`, `PropagationParent` | Defender-internal correlation and propagation, not external ETW input. |

## What To Focus On For Event Generation

If the goal is to find where external events become Defender events, focus on these layers in order:

1. Domain adapters: `FUN_180122690`, `FUN_180123120`, `FUN_1806163d0`, `FUN_1805eeab0`, `FUN_180a6c4a0`.
2. Main input callbacks: `QueueRtpNotification`, `QueueExtendedRtpNotification`.
3. Object creation: `NotificationFactory` / `FUN_180124570`.
4. Routing: `QueueBmNotification`, `SubmitNotificationToProcessContext`.
5. Final enqueue: `ProcessContextPushNotification`.

`ProcessContextPushNotification` is the important enqueue point, but not the external event source. The external event source is the RSIG/RTP or extended RTP callback path, and the factory is where raw telemetry is materialized into Defender's internal notification objects.


## Domains

**Domains**
The `1`, `2`, `8`, `9` values are raw RTP/BM input domains, not BM event types.

- Normal `QueueRtpNotification` layout: domain at `event+0x8`, event/type-ish field logged from `event+0x18`.
- Extended layout: domain at `event+0x10`, corresponding type field logged from `event+0x20`.
- The domain selects a factory/callback lane. The resulting internal `INotification` has its own notification type returned by the vtable.

What I found:

| Domain | Adapter | Meaning from code |
|---:|---|---|
| `1` | `FUN_180122690` | Basic RTP notification lane. Validates domain and forwards directly to the registered queue callback. |
| `2` | `FUN_180123120` | Process-context/lifecycle-heavy lane. Requires extra payload pointer, runs side callbacks at controller offsets `+0x20`, `+0x30`, `+0x28`, then forwards to the main queue callback. |
| `8` | `FUN_1806163d0` | Secondary RTP/BM lane. Thin validator/forwarder; semantics are determined later by the factory-created notification object. |
| `9` | `FUN_1805eeab0` | Another secondary RTP/BM lane. Also thin validator/forwarder. I do not see evidence that this is related to the global threadpool’s bucket `9`; same number, different layer. |

The common path is:

```text
domain adapter
  -> FUN_180123a0c
  -> QueueRtpNotification
  -> notification factory
  -> QueueBmNotification
  -> SubmitNotificationToProcessContext
  -> ProcessContextPushNotification
```

## Remote Thread Creation

The notification you’re asking about maps to `RemoteThreadCreate`.

Two relevant IDs exist:

| Layer | Type |
|---|---|
| Internal notification/report type | `0x21` |
| BM behavior event code | `0x400e` / `BM_RemoteThreadCreate` |

The clearest formatter/consumer is:

```text
FUN_180455d20
```

It checks:

```c
notification_type == 0x21
```

`FUN_1804525c8(0x21)` maps it to domain string:

```text
System
```

`FUN_180452370(0x21)` maps it to type string:

```text
RemoteThreadCreate
```

Data fields used by `FUN_180455d20`:

| Field | Offset / source |
|---|---|
| Source process id | notification header `piVar5[3]` |
| Source process creation time | notification header qword at `piVar5+1` |
| Sequence id | notification header qword at `piVar5+6` |
| Target process id | notification object `+0xd0` |
| Target process creation time | notification object `+0xc8` |
| Target thread id | notification object `+0xdc` |
| Target thread creation time | notification object `+0xd4` |
| Target image name | notification object `+0xe0` |
| Optional short target image name | resolved from target image path |

It emits/report-formats this XML-style payload:

```text
<RemoteThreadCreate
  TargetProcessId="%u"
  TargetProcessCreationTime="%llu"
  TargetThreadId="%u"
  TargetThreadCreationTime="%llu"
  TargetImageName="%s">
```

There is also a later behavior-module emission site:

```text
FUN_180561790
```

That function issues:

- `0x400e` = `BM_RemoteThreadCreate`
- `0x402e` = `BM_Etw_CodeInjection`, tagged with `"remotethread"`
- `0x408a` = `BM_Etw_V2CodeInjection`, with data like `imagename:%ls;targetprocessppid:%lu:%llu` and tag `injectiontype:remotethread;`

So: queue-side internal notification type is `0x21` (`System/RemoteThreadCreate`), while the BM behavior event name table calls the same activity `0x400e BM_RemoteThreadCreate`.


# Thread Creation Notification 

`FUN_180561790` is the remote-thread-create handling path that turns a queued notification into BM behavior-module events and taints/reinspects the target process.

**High-Level Flow**
1. Gets the BM metastore with `Bm_GetMetaStore`.
2. Extracts/resolves the target image path from the notification via `FUN_180561d00`.
3. Checks whether this is actually cross-process:
   - It compares notification target process identity at `param_3+0xc8/+0xd0` with the source notification process identity returned by the notification vtable.
   - If source and target are same process, it skips the remote-thread behavior emission.
4. Looks up a prior verdict/cache entry for the target process with `Bm_MetaStoreLookupVerdict(..., cacheMode=2)`.
5. If verdict bit `2` is set, it skips emission.
6. Gets the current process-context image path and calls `FUN_1801da920`, which appears to mark/taint/reinspect the target process for injection context.
7. Extracts the filename component from the target image path with `FindLastWideChar(..., '\\') + 2`.
8. Emits three behavior-module events.

**The Three Emissions**
The actual behavior-module emission calls are all `EmitBehaviorModuleEvent(...)`.

1. `BM_RemoteThreadCreate`

```c
event.code = 0x400e; // BM_RemoteThreadCreate
event.flags = 0x400000;
event.image_name = basename(target_image_path);
EmitBehaviorModuleEvent(..., &event);
```

This is the direct behavior event: remote thread creation into the target image.

2. `BM_Etw_CodeInjection`

```c
event.code = 0x402e; // BM_Etw_CodeInjection
event.flags1 = 0x400000;
event.flags2 = 0x400000;
event.tag = L"remotethread";
event.image_name = basename(target_image_path);
EmitBehaviorModuleEvent(..., &event);
```

This reclassifies the same activity as generic code injection with the injection subtype `remotethread`.

3. `BM_Etw_V2CodeInjection`

It first builds a detail string:

```text
imagename:%ls;targetprocessppid:%lu:%llu
```

Using:
- `%ls` = basename target image
- `%lu` = target process id from `param_3+0xd0`
- `%llu` = target process creation time from `param_3+0xc8`

Then emits:

```c
event.code = 0x408a; // BM_Etw_V2CodeInjection
event.data = L"imagename:...;targetprocessppid:pid:ctime";
event.flags1 = 0x400000;
event.flags2 = 0x400000;
event.tag = L"injectiontype:remotethread;";
EmitBehaviorModuleEvent(..., &event);
```

**Important Offsets**
For the remote-thread notification object (`param_3`):

| Offset | Meaning |
|---:|---|
| `+0xc8` | target process creation time |
| `+0xd0` | target process id |
| `+0xe0` | target image path string |

The source process identity comes from the notification header returned by the vtable call:

| Header field | Meaning |
|---|---|
| `header+0x04` / `header+0x08` style tuple | source process creation time |
| `header+0x0c` | source process id |

**Net Effect**
`FUN_180561790` says: if a process creates a thread in another tracked process, and the target is not already verdict-suppressed, emit behavior evidence for remote-thread injection under three names: direct `BM_RemoteThreadCreate`, generic `BM_Etw_CodeInjection`, and richer `BM_Etw_V2CodeInjection`. It also marks/reinspects the target process so later BM logic treats it as tainted/injection-related.