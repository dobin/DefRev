# ETW Consumers

High-level notes from the BM ETW consumer path. Provider names are mostly not present as strings; event kinds below are inferred from dispatcher logic, event IDs, property names, and emitted `BM_Etw_*` behavior names.

## Subscription / Callback Path

| Function | Address | Role | Events consumed |
| --- | --- | --- | --- |
| `EtwControllerImpl_Initialize` | `0x180b0c194` | Opens real-time ETW traces and registers the record callback. | Subscribes to `DefenderApiLogger`, `DefenderAuditLogger`, and `DefenderApiLoggerLowPriv`. |
| `BmEtw_EventRecordCallback` | `0x180129840` | Main ETW `EVENT_RECORD` callback. | Receives raw ETW records from the trace sessions and forwards them to BM metastore ETW handling. |
| `BmEtw_MetaStoreSinkDispatchRecord` | `0x1805d7164` | Thin forwarding wrapper. | Passes ETW records into the main dispatcher. |
| `BmEtw_DispatchEventRecord` | `0x1805d71bc` | Central ETW classifier/router. | Filters self/disabled events, classifies provider GUIDs, maps provider event IDs, and calls family-specific handlers. |
| `BmEtw_ClassifyProviderGuid` | `0x1805ba57c` | Provider GUID classifier. | Recognizes multiple provider families by GUID constants. Names are not embedded. |
| `BmEtw_MapProviderEventToIndex` | `0x18057071c` | Provider event-ID mapper. | Maps `(provider family, event id)` to Defender internal ETW event indexes gated by `MpBmEtwEventList*`. |

## Event Family Handlers

| Function | Address | Event kind consumed |
| --- | --- | --- |
| `BmEtw_DispatchApiCallEventFamily` | `0x1803a6650` | API/process manipulation events: `PsSetLoadImageNotifyRoutine`, terminate process, write memory, set thread context, open process, open thread, shutdown registration style events. |
| `BmEtw_DispatchKernelProcessEventFamily` | `0x180184570` | Kernel/process-thread style events, including process/thread lifecycle and remote-thread/memory-map/protect related event IDs. |
| `BmEtw_DispatchThreatIntProcessThreadEvent` | `0x1801868e0` | Threat-intelligence-like process/thread/memory events: code injection, VM allocate/protect/read/map, suspend/resume thread/process, driver/device load/unload, exploit/dangerous syscall events. |
| `BmEtw_DispatchAuditSecurityEvent` | `0x180620a28` | Audit/security events: logon success/failure, scheduled task create/update, account/user/password changes, LDAP/search, hive history clear, credential/vault access. |
| `BmEtw_DispatchBlockExploitEventFamily` | `0x1806f35c4` | Exploit-protection/block-exploit events; emits `BM_Etw_BlockExploit`. |
| `BmEtw_DispatchSetWindowsHookEventFamily` | `0x1808566a4` | SetWindowsHook-style event; emits `BM_Etw_SetWindowsHook`. |
| `BmEtw_DispatchLogClearEventFamily` | `0x1807db460` | Log clear events: security/application/system log clear. |
| `BmEtw_DispatchWmiActivityEventFamily` | `0x180b0cc24` | WMI execution events: WMI exec method / WMI create process, local or remote origin. |
| `BmEtw_DispatchLdapSearchEventFamily` | `0x1806b4504` | LDAP search event. |
| `BmEtw_HandleBitsCreateEvent` | `0x180705348` | BITS job create event; extracts title/owner style fields. |
| `BmEtw_DispatchCredentialVaultEventFamily` | `0x18067ac0c` | Credential and Vault API event group, such as credential read/enumerate/backup and vault enumerate/find/get. |
| `BmEtw_DispatchServiceControlEventFamily` | `0x180632b40` | Service control events: service host/started/stopped and service configuration changes. |
| `BmEtw_DispatchClrRuntimeEventFamily` | `0x1804dd1c0` | CLR module load / CLR assembly load events. |
| `BmEtw_HandleAmsiInitFailedEvent` | `0x18034ae60` | AMSI init failure event (`ScanContent-InitFail`). |
| `BmEtw_HandleClipboardAggregateEvent` | `0x180b0c8c4` | Clipboard aggregate/write event (`UiWriteClipboardAggregate` / `BM_Etw_ClipWrite`). |

## Code Injection / Memory Handlers

| Function | Address | Event kind consumed |
| --- | --- | --- |
| `BmEtw_ReportRemoteAllocVmCodeInjection` | `0x180639f68` | Remote virtual-memory allocation used as code-injection signal. Emits `BM_Etw_CodeInjection` with `allocvmremote`. |
| `BmEtw_HandleProtectVmCodeInjectionEvent` | `0x180185248` | Virtual-memory protection change used as code-injection signal. Reads target process identity, VM base/size, protection mask, previous protection mask, and optional mapped file name; emits `BM_Etw_CodeInjection` with `protectvm`. |
| `BmEtw_EmitThreadOrRemoteThreadBehavior` | `0x180187dc8` | Thread/process suspend/resume or remote-thread behavior events. Emits `BM_Etw_SuspendThread`, `BM_Etw_ResumeThread`, `BM_Etw_SuspendProcess`, or `BM_Etw_ResumeProcess`. |
| `BmEtw_EmitDangerousSyscall` | `0x18036b89c` | Dangerous syscall event. Emits `BM_Etw_DangerousSyscall`. |
| `BmHandleEtwCodeInjectionEvent` | `0x180189e90` | Downstream normalized code-injection handler, not the raw ETW callback. Converts ETW-derived code-injection behavior into richer `BM_Etw_V2CodeInjection` reports with injection type and target process details. |

## Additional Renamed Leaf Handlers

| Function | Address | Event kind consumed |
| --- | --- | --- |
| `BmEtw_EmitBlockExploitEvent` | `0x1806f3628` | Emits `BM_Etw_BlockExploit`; distinguishes user/kernel origin and includes exploit details. |
| `BmEtw_EmitSetWindowsHookEvent` | `0x1808566f8` | Emits `BM_Etw_SetWindowsHook` after metastore/process checks. |
| `BmEtw_EmitCredentialProcessEvent` | `0x18067b7b0` | Credential/vault process event variant with process path, command line, protection, and optional child process fields. |
| `BmEtw_EmitCredentialImageEvent` | `0x18067ac88` | Credential/vault image event variant with image name and process protection fields. |
| `BmEtw_EmitCredentialModuleEvent` | `0x18074c290` | Credential/vault module event variant with module path, memory module path, and API name fields. |
| `BmEtw_EmitCredentialHookedApiEvent` | `0x1806f5f0c` | Credential/vault hooked-API event variant with hooked API, return/called/target/stack addresses, and return module path. |
| `BmEtw_EmitServiceHostStartedEvent` | `0x1806339e4` | Emits service-host-started behavior. |
| `BmEtw_EmitBasicServiceEvent` | `0x180633c88` | Emits basic service start/stop/configuration behavior variants. |
| `BmEtw_EmitServiceChangeBinaryPathEvent` | `0x180632c1c` | Emits service binary-path change behavior. |
| `BmEtw_EmitServiceChangeAccountInfoEvent` | `0x180632ed8` | Emits service account-info change behavior with service metadata. |
| `BmEtw_EmitClrModuleLoadEvent` | `0x1804dd7e0` | Emits `BM_Etw_CLRModuleLoad`. |
| `BmEtw_EmitClrAssemblyLoadEvent` | `0x1804dd3ec` | Emits `BM_Etw_CLRAssemblyLoad`. |

## Notable Emitted Event Names

Observed normalized behavior names include `BM_Etw_CodeInjection`, `BM_Etw_V2CodeInjection`, `BM_Etw_AllocVmLocal`, `BM_Etw_ProtectVmLocal`, `BM_Etw_ReadVmRemote`, `BM_Etw_MapViewLocal`, `BM_Etw_OpenProcess`, `BM_Etw_OpenThread`, `BM_Etw_SetThreadContext`, `BM_Etw_WriteMemory`, `BM_Etw_TerminateProcess`, `BM_Etw_LogonSuccess`, `BM_Etw_LogonFailure`, `BM_Etw_ScheduledTaskCreate`, `BM_Etw_WMIExecMethod`, `BM_Etw_WMICreateProcess`, `BM_Etw_CLRModuleLoad`, `BM_Etw_CLRAssemblyLoad`, `BM_Etw_AmsiInitFailed`, and `BM_Etw_ClipWrite`.