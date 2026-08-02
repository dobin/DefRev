## Memory Scan ETW


1) `VirtualAlloc()` 
2) `WriteProcessMemory()`
3) Sleep 5 seconds
4) `VirtualProtectEx()` -> RWX
5) Sleep 5 seconds
6) `CreateRemoteThread()` 


```
PS C:\Users\hacker\Desktop\b> .\redtest3.exe 2
==============================================
Red Team Test Tool - APC & Process Injection
==============================================

2026-06-29 07:56:30.953 UTC [+] Generating 100 KB of random shellcode data...
2026-06-29 07:56:30.968 UTC [+] Shellcode initialized at 0x000002406AC84C70 (size: 102400 bytes)

=== TEST 2: Process Spawn with Shellcode Allocation ===

2026-06-29 07:56:30.968 UTC [Main] Spawning child process (notepad.exe)...
2026-06-29 07:56:31.046 UTC [Main] Process created - PID: 4868, TID: 3744
2026-06-29 07:56:31.046 UTC [Main] Allocated 102400 bytes at 0x00000221E3A70000 in target process
2026-06-29 07:56:31.046 UTC [Main] Wrote 102400 bytes of shellcode to target process

2026-06-29 07:56:31.046 UTC Wait 5 seconds before changing memory protections...
2026-06-29 07:56:36.064 UTC [Main] Changed memory protection to PAGE_EXECUTE_READ
2026-06-29 07:56:36.064 UTC [Main] Shellcode address: 0x00000221E3A70000

2026-06-29 07:56:36.064 UTC Wait 5 seconds before executing shellcode in the target process...
2026-06-29 07:56:41.077 UTC [Main] Creating remote thread to execute shellcode...
2026-06-29 07:56:41.077 UTC [Main] Remote thread created successfully (TID: 3568)
2026-06-29 07:56:41.078 UTC [Main] Resuming child process...
2026-06-29 07:56:41.078 UTC [Main] Waiting for remote thread to complete...
2026-06-29 07:56:41.109 UTC [Main] Process is running. Waiting a second before terminating...
2026-06-29 07:56:42.415 UTC [Main] Terminating child process...
2026-06-29 07:56:42.515 UTC [Main] Test 2 done
```

Or in short:
```
Process Start:        07:56:30.953
VirtualProtectEx():   07:56:36.064  # +5s
CreateRemoteThread(): 07:56:41.077  # +5s
```


1) `VirtualAlloc()` 
2) `WriteProcessMemory()`

3) Sleep 5 seconds
4) `VirtualProtectEx()` -> RWX
->  MsMpEng.exe scans? None observed

5) Sleep 5 seconds
6) `CreateRemoteThread()` 
->  MsMpEng.exe scans? One observed

All ETW events: <file.json>

The relevant recorded ETW events:
![Defender ETW events](/defender/rededr-redtest-long-openprocess-minimal.png)


We see: 
* ETW-TI PROTECTVM event of the VirtualProtect()
* Kernel-Process ThreadStart event of the CreateRemoteThread()
* 3 openprocess by MsMpEng.exe, the middle one with VM_READ

We can conclude that `CreateRemoteThread()` triggered a memory scan, as immediately afterwards
`MsMpEng.exe` opens the process with VM_READ (desiredaccess 0x1410).

Note that `VirtualProtectEx()`, which remotely changes the memory region to RWX, didnt result
in any actions by defender (no events in the 5s window). 

Therefore we are interested in the following Defender callstack:

![Defender openprocess callstack](/defender/rededr-redtest-long-openprocess-minimal-defender.png)

Where mpengine.dll has the following base addres:

```
name: mpengine.dll base: 0x7ffeefb40000 size: 0x11f1000
```

---

AI MpMpEng.exe memory scan triggered by CreateRemoteThread()

InvokeModuleScanCallbacks 
ModuleTrustEvaluationCall 

---

## Callstack Analysis

Here is the analysis of the Defender stack trace. The call chain shows Defender's **Real-Time Protection** processing a suspicious image load event, ultimately performing a **process hollowing check** that requires calling `OpenProcess` on the target process.

this is a stack trace of defender, from an ETW event which was emitted when defender called OpenProcess() on a suspicous process. Analyze the functions in mpengine.dll, and tell me what they are doing using Ghidra tools. also write me an overview table with likely translation of the names of the functions involved in the stacktrace.

```
mpengine.dll base: 0x7ffeefb40000 name: mpengine.dll size: 0x11f1000

addr: 0x7fff078112c4 addr_info: ntdll.dll idx: 0x0
addr: 0x7fff04dd246e addr_info: KERNELBASE.dll idx: 0x1
addr: 0x7ffeefc783ce addr_info: mpengine.dll idx: 0x2
addr: 0x7ffeefc781c7 addr_info: mpengine.dll idx: 0x3
addr: 0x7ffeefdd33d7 addr_info: mpengine.dll idx: 0x4
addr: 0x7ffeefdd3010 addr_info: mpengine.dll idx: 0x5
addr: 0x7ffeefc66c8e addr_info: mpengine.dll idx: 0x6
addr: 0x7ffeefc65ae0 addr_info: mpengine.dll idx: 0x7
addr: 0x7ffeefc65911 addr_info: mpengine.dll idx: 0x8
addr: 0x7ffeefc6512c addr_info: mpengine.dll idx: 0x9
addr: 0x7ffeefc64fd6 addr_info: mpengine.dll idx: 0xa
addr: 0x7ffeefc648d5 addr_info: mpengine.dll idx: 0xb
addr: 0x7ffeefc64694 addr_info: mpengine.dll idx: 0xc
addr: 0x7ffef042f698 addr_info: mpengine.dll idx: 0xd
addr: 0x7ffef042f583 addr_info: mpengine.dll idx: 0xe
addr: 0x7fff077d28ea addr_info: ntdll.dll idx: 0xf
addr: 0x7fff077a5eb6 addr_info: ntdll.dll idx: 0x10
addr: 0x7fff05b6259d addr_info: KERNEL32.DLL idx: 0x11
addr: 0x7fff077caf78 addr_info: ntdll.dll idx: 0x12
```

### Overview Table

| Idx | Offset | Ghidra Address | Function Name (Renamed) | Likely Microsoft Name |
|-----|--------|---------------|--------------------------|----------------------|
| 0x0 |  |  | `ntdll.dll` | `NtOpenProcess` (syscall) |
| 0x1 |  |  | `KERNELBASE.dll` | `OpenProcess` (win32 API) |
| **0x2** | `0x1383CE` | `0x180138358` | `OpenProcessWithAccess` | `MpOpenProcessByPid` / `CProcessAccessHelper::Open` |
| **0x3** | `0x1381C7` | `0x1801381A0` | `AcquireProcessHandleForScan` | `AcquireScanProcessHandle` |
| **0x4** | `0x2933D7` | `0x180293358` | `CheckProcessHollowing` | `CheckForProcessHollowing` / `ScanMemoryLayout` |
| **0x5** | `0x293010` | `0x180292FF4` | `ProcessScanCleanup` | `ProcessScanTeardown` / `FinalizeScanResults` |
| **0x6** | `0x126C8E` | `0x180125E00` | `ClassifyImageModule` | `ClassifyImageLoadEvent` / `EvaluateTrustedModule` |
| **0x7** | `0x125AE0` | `0x180125A70` | `ModuleTrustEvaluationCall` | `EvaluateModuleTrust` |
| **0x8** | `0x125911` | `0x1801258B0` | `ModuleCallbackRouter` | `DispatchModuleCallback` |
| **0x9** | `0x12512C` | `0x180125080` | `InvokeModuleScanCallbacks` | `InvokeAllScanHandlers` |
| **0xA** | `0x124FD6` | `0x180124F68` | `AnalyzeImageLoadEvent` | `ProcessImageLoadNotification` |
| **0xB** | `0x1248D5` | `0x180124780` | `ProcessScanQueue` | `ProcessScanItem` / `ProcessPendingScanQueue` |
| **0xC** | `0x124694` | `0x180124640` | `ScanItemWaitAndDispatch` | `WaitForScanItemAndDispatch` |
| **0xD** | `0x8EF698` | `0x1808EF63C` | `ProcessSingleWorkItem` | `ProcessScannedItem` / `HandleScanResult` |
| **0xE** | `0x8EF583` | `0x1808EF4A4` | `ThreatAnalysisWorkerThread` | `ThreatAnalysisWorker` / `ScanWorkerThread` |
| 0xF |  |  | `ntdll.dll` | `TppWorkerThread` |
| 0x10 |  |  | `ntdll.dll` | `TppWaipCallback` |
| 0x11 |  |  | `KERNEL32.DLL` | `BaseThreadInitThunk` |
| 0x12 |  |  | `ntdll.dll` | `RtlUserThreadStart` |


### Details

#### 1. `ThreatAnalysisWorkerThread` (0x8EF4A4 / idx 0xE)
**Role:** Thread pool worker that processes the scan work queue. Uses a critical section + counter to throttle concurrency. Calls `ProcessSingleWorkItem` for each queued item. This is the main loop of the background threat analysis worker thread.

#### 2. `ProcessSingleWorkItem` (0x8EF63C / idx 0xD)
**Role:** Dispatches a single work item to the appropriate handler. Emits ETW events via `FUN_1808EFF20` / `FUN_1808EFE7C` (telemetry wrappers). The actual handler is called through an indirect dispatch (`guard_dispatch_icall`). This is the work item dispatcher.

#### 3. `ScanItemWaitAndDispatch` (0x124640 / idx 0xC)
**Role:** Waits on a semaphore (500ms timeout) for a scan item to become available. When one is ready, calls `ProcessScanQueue` to process it, then signals completion. This is the semaphore-based gate for the scan processing loop.

#### 4. `ProcessScanQueue` (0x124780 / idx 0xB)
**Role:** The main scan item processor. Dequeues items from a linked list queue (offset `+0x48`), enters critical sections, and dispatches based on scan type:
- **Type 1** (image load): Sets a flag, calls `Bm_GetMetaStore`, increments counter
- **Type 2, 5, 0x2D, 0x29, 3**: Queues into separate lists for batch processing
- Calls `AnalyzeImageLoadEvent` for the actual scan work
- Handles rate limiting via timestamp checks at `+0xA70`

#### 5. `AnalyzeImageLoadEvent` (0x124F68 / idx 0xA)
**Role:** Processes a single image load notification. Sets flag `+0xA67 = 1`, dispatches to specific handlers:
- `FUN_180625C78` for types 1, 0x29, 3 (image load classification)
- `FUN_180B03F18` for type 0x1F (process creation)
- Calls `InvokeModuleScanCallbacks` to run all registered scan callbacks
- Increments global tracker `DAT_1810C6288` (scan counter)

#### 6. `InvokeModuleScanCallbacks` (0x125080 / idx 0x9)
**Role:** Iterates over a list of registered scan callbacks at `+0x200`. For each callback, calls `ModuleCallbackRouter`. If callbacks fail or report "not trusted", calls `FUN_18012A2C0` (additional investigation). Also processes a secondary queue at `+0x508` calling `FUN_18074E074` (deep process inspection).


#### 7. `ModuleCallbackRouter` (0x1258B0 / idx 0x8)
**Role:** Router function that dispatches to the correct callback implementation based on the vtable at `*param_3 + 0x28`:
- `FUN_180125A70`  `ModuleTrustEvaluationCall` (trust evaluation)
- `FUN_180125D20`  (cloud lookup / MAPS)
- `FUN_1805DD320`  (behavioral analysis)

#### 8. `ModuleTrustEvaluationCall` (0x125A70 / idx 0x7)
**Role:** Calls `FUN_1805616F0` (filter/pre-check) and then dispatches to the actual classifier:
- `ClassifyImageModule` (0x125E00)  the main trust classifier
- `FUN_1804D05C0`  alternative classifier

#### 9. `ClassifyImageModule` (0x125E00 / idx 0x6)
**Role:** This is the **core trust/classification engine**. It is a large function (~2000+ lines) that:
- Gets metadata from `Bm_GetMetaStore`
- Handles multiple scan types:
  - **Type 1** (initial image load): Performs friendly/trust checks via `FUN_1801AB408`, checks exclusions, checks `IsKnownFriendly` via Lua scripts, checks ASR Office Block Injection rules
  - **Type 3** (re-inspection): Query code signing info, checks signer/cdhash/teamid
  - **Type 5** (trust check): Gets `Bm_GetImageNameConfigProvider`, checks process/code signing
  - **Type 6** (module load): Friendly trust check, ASR checks
  - **Type 0x29, 0x2D**: Code signing / verdict evaluation
- Calls `FUN_180292FF4` (ProcessScanCleanup) at the end of each scan type
- Calls `Bm_ReinspectTrackedProcess` for suspect processes
- Logs "Module load (%ls) %ls trusted" via `FUN_1808E1808`

#### 10. `ProcessScanCleanup` (0x292FF4 / idx 0x5)
**Role:** Runs finalization steps after a module scan:
- `FUN_180293084`  initialization/setup
- `CheckProcessHollowing`  memory integrity check
- `FUN_180293174`  teardown
- If `param_2 == 2` (cleanup): resets all flags (0x7B0-0x7B4, 0x799), closes saved handle at `+0x7A8`

#### 11. `CheckProcessHollowing` (0x293358 / idx 0x4)
**Role:** **This is the key function that triggered the OpenProcess call.** It detects process hollowing:
- Checks if hollowing detection is disabled (`DAT_1810ADE21`  "MpDisableProcessHollowingChecks")
- Checks flags `+0x7B1` (already checked) and `+0x7B2` (already detected)
- Calls `AcquireProcessHandleForScan` to open the target process
- If prior hollowing check failed (error 299): logs and skips
- Otherwise: iterates memory regions using `VirtualQueryEx`:
  - Checks if protection is non-standard (not in `0x10-0x30` range, not in bitmask, not `0x80`)
  - Checks if type is `MEM_IMAGE` (0x1000000)
  - If type is NOT `MEM_IMAGE` (i.e., private/allocated memory): **logs "Hollow1" alert** and sets flag `+0x7B2 = 1`
- Accumulates region sizes until target size is reached
- Closes the process handle

#### 12. `AcquireProcessHandleForScan` (0x1381A0 / idx 0x3)
**Role:** Wraps the process handle acquisition. Calls `OpenProcessWithAccess`, validates the PID hasn't changed (compares creation time), and invalidates the handle if the process has been replaced.

#### 13. `OpenProcessWithAccess` (0x138358 / idx 0x2)
**Role:** The actual `OpenProcess()` wrapper. Allocates a handle struct, calls `OpenProcess(access, FALSE, pid)`, calls `GetProcessTimes()` to store creation time. Uses access flags that include `0x400` (
PROCESS_QUERY_INFORMATION) and optionally `0xC00` (PROCESS_VM_READ + PROCESS_VM_OPERATION) depending on `FUN_180138584`.


### Summary

The stack trace shows Defender's Real-Time Protection pipeline:

```
Worker Thread  Process Work Item  Wait for Scan Item  Process Queue 
Analyze Image Load  Invoke Callbacks  Route Callback  Trust Evaluation 
Classify Module  Cleanup  Check Process Hollowing  Open Process  OpenProcess()
```

The **trigger** was a suspicious image load event. During the classification phase, the scanner determined the module needed deeper inspection. The cleanup phase then invoked `CheckProcessHollowing`, whic
h called `OpenProcess()` (via `OpenProcessWithAccess`) to read the target process's memory layout and detect if the process was hollowed (code injection via process replacement).

