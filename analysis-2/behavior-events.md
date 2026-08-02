# Behavior Events

High-level list of ETW-derived Defender Behavior Monitoring events observed in the ETW consumer path. These are internal normalized `BM_Etw_*` behavior names emitted after raw ETW records are decoded and routed.

| Behavior event | Description |
| --- | --- |
| `BM_Etw_CodeInjection` | Generic code-injection behavior. Used for remote VM allocation, VM protection changes, and similar injection signals. |
| `BM_Etw_V2CodeInjection` | Richer code-injection report with injection type and target process details. |
| `BM_Etw_AllocVmLocal` | Local virtual-memory allocation event. |
| `BM_Etw_ProtectVmLocal` | Local virtual-memory protection change event. |
| `BM_Etw_ReadVmRemote` | Remote process memory read event. |
| `BM_Etw_ReadVmRemoteAgg` | Aggregated remote process memory read event. |
| `BM_Etw_MapViewLocal` | Local memory section/map-view event. |
| `BM_Etw_SetThreadContext` | Thread context modification event. Often relevant to injection behavior. |
| `BM_Etw_WriteMemory` | Process memory write event. |
| `BM_Etw_OpenProcess` | Process handle open event, usually with target process/access details. |
| `BM_Etw_OpenThread` | Thread handle open event, usually with target thread/access details. |
| `BM_Etw_TerminateProcess` | Process termination API event. |
| `BM_Etw_SuspendThread` | Thread suspension event. |
| `BM_Etw_ResumeThread` | Thread resume event. |
| `BM_Etw_SuspendProcess` | Process suspension event. |
| `BM_Etw_ResumeProcess` | Process resume event. |
| `BM_Etw_DangerousSyscall` | Dangerous or suspicious syscall event. |
| `BM_Etw_PsSetLoadImageNotifyRoutine` | Kernel image-load callback registration event. |
| `BM_Etw_LoadDriver` | Driver load event. |
| `BM_Etw_UnloadDriver` | Driver unload event. |
| `BM_Etw_LoadDevice` | Device load event. |
| `BM_Etw_UnloadDevice` | Device unload event. |
| `BM_Etw_BlockExploit` | Exploit-protection/block-exploit event. |
| `BM_Etw_ExploitProtection` | Exploit protection related event. |
| `BM_Etw_SetWindowsHook` | Windows hook registration event. |
| `BM_Etw_SetEventHook` | Event hook registration event. |
| `BM_Etw_GetAsyncKeyState` | Keyboard state polling event. |
| `BM_Etw_RegisterInputDevices` | Raw input device registration event. |
| `BM_Etw_ClearLog` | Windows event log clear event. |
| `BM_Etw_WMIActivityNew` | WMI activity event. |
| `BM_Etw_WMIExecMethod` | WMI method execution event. |
| `BM_Etw_WMICreateProcess` | WMI process creation event, including local/remote origin details. |
| `BM_Etw_BITSCreate` | BITS job creation event. |
| `BM_Etw_ScheduledTaskCreate` | Scheduled task creation event. |
| `BM_Etw_ScheduledTaskUpdate` | Scheduled task modification event. |
| `BM_Etw_LogonSuccess` | Successful logon audit event. |
| `BM_Etw_LogonFailure` | Failed logon audit event. |
| `BM_Etw_UserAccountCreated` | User account creation event. |
| `BM_Etw_UserAccountChanged` | User account modification event. |
| `BM_Etw_AccountPasswordChanged` | Account password changed event. |
| `BM_Etw_AccountPasswordReset` | Account password reset event. |
| `BM_Etw_LDAPSearch` | LDAP search event. |
| `BM_Etw_HiveHistoryClear` | Registry hive history clear event. |
| `BM_Etw_CredReadCredentials` | Credential read event. |
| `BM_Etw_CredBackupCredentials` | Credential backup event. |
| `BM_Etw_CredEnumerate` | Credential enumeration event. |
| `BM_Etw_CredReadDomainCredentials` | Domain credential read event. |
| `BM_Etw_CredFindBestCredential` | Best-match credential lookup event. |
| `BM_Etw_CredReadByTokenHandle` | Credential read using a token handle. |
| `BM_Etw_VaultFindCredentials` | Vault credential lookup event. |
| `BM_Etw_VaultEnumerateCredentials` | Vault credential enumeration event. |
| `BM_Etw_VaultGetUniqueCredential` | Vault unique credential retrieval event. |
| `BM_Etw_ServiceHostStarted` | Service host start event. |
| `BM_Etw_ServiceStarted` | Service start event. |
| `BM_Etw_ServiceStop` | Service stop event. |
| `BM_Etw_ServiceChangeStartType` | Service start-type change event. |
| `BM_Etw_ServiceChangeBinaryPath` | Service binary path change event. |
| `BM_Etw_ServiceChangeAccountInfo` | Service account information change event. |
| `BM_Etw_CLRModuleLoad` | CLR module load event. |
| `BM_Etw_CLRAssemblyLoad` | CLR assembly load event. |
| `BM_Etw_AmsiInitFailed` | AMSI initialization failure event. |
| `BM_Etw_ClipWrite` | Clipboard write/aggregate event. |
| `BM_Etw_CreateLink` | Link creation event. |
| `BM_Etw_RegisterShutdown` | Shutdown registration event. |
| `BM_Etw_RegisterLastShutdown` | Last-shutdown registration event. |
| `BM_Etw_NtAdjustPrivileges` | Privilege adjustment event. |

These events are emitted through `BmEtw_EmitBehaviorEvent` and usually become internal BM `EtwEvent` notifications before being routed through process context, metastore, and reporting logic.

## Example Payloads

These examples show the normalized behavior payloads built by ETW handlers before they are queued as internal `EtwEvent` notifications. Field names are taken from strings used by the converters where visible.

### `BM_Etw_CodeInjection` / Protect VM

Emitter: `BmEtw_HandleProtectVmCodeInjectionEvent`

Purpose: virtual-memory protection change treated as a code-injection signal.

```text
Behavior ID: BM_Etw_CodeInjection
Primary: target process image/name
Secondary: "protectvm"
Extra fields:
  TargetProcessId
  TargetProcessCreateTime
  vmbaseaddress
  vmregionsize
  protectionmask
  lastprotectionmask
  optional vavadmmfname
Process identity: source/target PersistentProcessID
```

### `BM_Etw_CodeInjection` / Remote Alloc VM

Emitter: `BmEtw_ReportRemoteAllocVmCodeInjection`

Purpose: remote virtual-memory allocation treated as a code-injection signal.

```text
Behavior ID: BM_Etw_CodeInjection
Primary: target process image/name
Secondary: "allocvmremote"
Extra fields:
  TargetProcessId
  TargetProcessCreateTime
  vmbaseaddress
  localvmallocregionsize
Process identity: source/target PersistentProcessID
```

### `BM_Etw_OpenProcess`

Emitter: `BmEtw_EmitOpenProcess`

Purpose: process handle open event.

```text
Behavior ID: BM_Etw_OpenProcess
Primary: target process short image name
Secondary: requested/access detail string from ETW
Extra fields:
  apiresults
Process identity: caller process identity
```

### `BM_Etw_OpenThread`

Emitter: `BmEtw_EmitOpenThread`

Purpose: thread handle open event.

```text
Behavior ID: BM_Etw_OpenThread
Primary: target process short image name
Secondary: requested/access detail string from ETW
Extra fields:
  threadid
  apiresults
Process identity: caller process identity
```

### `BM_Etw_SetThreadContext`

Emitter: `BmEtw_EmitSetThreadContext`

Purpose: thread context modification.

```text
Behavior ID: BM_Etw_SetThreadContext
Primary: empty/zero
Secondary: empty/zero
Extra fields:
  apiresults
Process identity: caller process identity
```

### `BM_Etw_TerminateProcess`

Emitter: `BmEtw_EmitTerminateProcess`

Purpose: process termination API event.

```text
Behavior ID: BM_Etw_TerminateProcess
Primary: target process short image name
Secondary: empty/zero
Extra fields:
  apiresults
Process identity: caller process identity
```

### `BM_Etw_PsSetLoadImageNotifyRoutine`

Emitter: `BmEtw_EmitPsSetLoadImageNotifyRoutine`

Purpose: kernel image-load callback registration.

```text
Behavior ID: BM_Etw_PsSetLoadImageNotifyRoutine
Primary: empty/zero
Secondary: empty/zero
Extra fields:
  callbackaddress
  apiresults
Process identity: event process identity
```

### Driver / Device Load Events

Emitter: `BmEtw_EmitDriverOrDeviceLoadEvent`

Purpose: driver/device load or unload activity.

```text
Behavior ID: BM_Etw_LoadDriver / BM_Etw_UnloadDriver / BM_Etw_LoadDevice / BM_Etw_UnloadDevice
Primary: empty/zero
Secondary: empty/zero
Extra fields:
  drivername
  driverpath
  apiresults
Process identity: event process identity
```

### `BM_Etw_BlockExploit`

Emitter: `BmEtw_EmitBlockExploitEvent`

Purpose: exploit-protection block event.

```text
Behavior ID: BM_Etw_BlockExploit
Primary: exploit target/detail string
Secondary: "user" or "kernel"
Extra fields:
  exploitinfo
Process identity: event process identity
```

### `BM_Etw_DangerousSyscall`

Emitter: `BmEtw_EmitDangerousSyscall`

Purpose: suspicious syscall event.

```text
Behavior ID: BM_Etw_DangerousSyscall
Primary: syscall/API name or event string
Secondary: detail string, if present
Extra fields: none observed in the final emit
Process identity: event process identity
```

### `BM_Etw_WMIExecMethod` / `BM_Etw_WMICreateProcess`

Emitter: `BmEtw_DispatchWmiActivityEventFamily`

Purpose: WMI operation, including WMI process creation.

```text
Behavior ID: BM_Etw_WMIExecMethod or BM_Etw_WMICreateProcess
Primary: target process short image name
Secondary: "local" or "remote"
Extra fields:
  operationmethodname
  for WMI create process: wmicreateprocessppid
  structured text may include CmdLine, MacFQDN, Origin
Process identity: event process identity
```

### `BM_Etw_BITSCreate`

Emitter: `BmEtw_HandleBitsCreateEvent`

Purpose: BITS job creation.

```text
Behavior ID: BM_Etw_BITSCreate
Primary: process / command context string
Secondary: structured title/owner string
Extra fields:
  title
  owner
Process identity: BITS job creator process identity
```

### `BM_Etw_ClearLog`

Emitter: `BmEtw_DispatchLogClearEventFamily`

Purpose: Windows event log clear.

```text
Behavior ID: BM_Etw_ClearLog
Primary: one of "seclogclr", "applogclr", "syslogclr"
Secondary: empty/zero
Extra fields: none observed
Process identity: event process identity
```

### `BM_Etw_ClipWrite`

Emitter: `BmEtw_HandleClipboardAggregateEvent`

Purpose: clipboard write/aggregate event.

```text
Behavior ID: BM_Etw_ClipWrite
Primary: clipboard source string
Secondary: clipboard detail string
Extra fields:
  clipsource
Process identity: process identity read from the event
```

### `BM_Etw_AmsiInitFailed`

Emitter: `BmEtw_HandleAmsiInitFailedEvent`

Purpose: AMSI initialization failure.

```text
Behavior ID: BM_Etw_AmsiInitFailed
Primary: AMSI action string, e.g. "ScanContent-InitFail"
Secondary: AMSI context string
Extra fields:
  amsiaction
  amsicontext
Process identity: event process identity
```

### `BM_Etw_CLRModuleLoad`

Emitter: `BmEtw_EmitClrModuleLoadEvent`

Purpose: CLR module load.

```text
Behavior ID: BM_Etw_CLRModuleLoad
Primary: CLR assembly/module ID
Secondary: formatted module summary
Extra fields:
  clrassemblyid
  clrflags
  clrmodulenativepath
  clrmoduleilpath
Process identity: event process identity
```

### `BM_Etw_CLRAssemblyLoad`

Emitter: `BmEtw_EmitClrAssemblyLoadEvent`

Purpose: CLR assembly load.

```text
Behavior ID: BM_Etw_CLRAssemblyLoad
Primary: CLR assembly ID
Secondary: formatted assembly summary
Extra fields:
  clrassemblyid
  clrflags
  clrassemblyname
Process identity: event process identity
```

### Service Events

Emitters: `BmEtw_DispatchServiceControlEventFamily`, `BmEtw_EmitServiceHostStartedEvent`, `BmEtw_EmitBasicServiceEvent`, `BmEtw_EmitServiceChangeBinaryPathEvent`, `BmEtw_EmitServiceChangeAccountInfoEvent`

Purpose: service start/stop and service configuration changes.

```text
Behavior ID: BM_Etw_ServiceStop / BM_Etw_ServiceStarted / BM_Etw_ServiceHostStarted /
             BM_Etw_ServiceChangeStartType / BM_Etw_ServiceChangeBinaryPath /
             BM_Etw_ServiceChangeAccountInfo
Primary: service name or service path string
Secondary: service detail string
Extra fields for account-info style events:
  loadordergroup
  svchostgroup
  critical
  userservice
  ownprocess
Process identity: event process identity
```

### Credential / Vault / Exploit Protection Style Events

Emitters: `BmEtw_DispatchCredentialVaultEventFamily` and its leaf emitters

Purpose: credential/vault API usage and related exploit-protection records.

```text
Behavior ID: usually BM_Etw_ExploitProtection for the observed leaf emitters
Primary: structured event summary
Secondary: structured details
Extra fields may include:
  eventid
  processpath
  processcommandline
  processprotection
  childimagepathname
  childcommandline
  imagename
  modulefullpath
  memmodulefullpath
  apiname
  hookedapi
  returnaddress
  calledaddress
  targetaddress
  stackaddress
  returnaddressmodulefullpath
Process identity: event process identity
```