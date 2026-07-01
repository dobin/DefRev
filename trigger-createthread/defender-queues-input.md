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
