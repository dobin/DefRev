
# Defender Callstack Details

Details of functions in index of callstack: 0x4, 0x5, 0x6

| Idx | Offset | Ghidra Address | Function Name (Renamed) | Likely Microsoft Name |
|-----|--------|---------------|--------------------------|----------------------|
| 0x0 |  |  | `ntdll.dll` | `NtOpenProcess` (syscall) |
| 0x1 |  |  | `KERNELBASE.dll` | `OpenProcess` (win32 API) |
| 0x2 | `0x1383CE` | `0x180138358` | `OpenProcessWithAccess` | `MpOpenProcessByPid` / `CProcessAccessHelper::Open` |
| 0x3 | `0x1381C7` | `0x1801381A0` | `AcquireProcessHandleForScan` | `AcquireScanProcessHandle` |
| **0x4** | `0x2933D7` | `0x180293358` | `CheckProcessHollowing` | `CheckForProcessHollowing` / `ScanMemoryLayout` |
| **0x5** | `0x293010` | `0x180292FF4` | `ProcessScanCleanup` | `ProcessScanTeardown` / `FinalizeScanResults` |
| **0x6** | `0x126C8E` | `0x180125E00` | `ClassifyImageModule` | `ClassifyImageLoadEvent` / `EvaluateTrustedModule` |
| 0x7 | `0x125AE0` | `0x180125A70` | `ModuleTrustEvaluationCall` | `EvaluateModuleTrust` |
| 0x8 | `0x125911` | `0x1801258B0` | `ModuleCallbackRouter` | `DispatchModuleCallback` |
| 0x9 | `0x12512C` | `0x180125080` | `InvokeModuleScanCallbacks` | `InvokeAllScanHandlers` |
| 0xA | `0x124FD6` | `0x180124F68` | `AnalyzeImageLoadEvent` | `ProcessImageLoadNotification` |
| 0xB | `0x1248D5` | `0x180124780` | `ProcessScanQueue` | `ProcessScanItem` / `ProcessPendingScanQueue` |
| 0xC | `0x124694` | `0x180124640` | `ScanItemWaitAndDispatch` | `WaitForScanItemAndDispatch` |
| 0xD | `0x8EF698` | `0x1808EF63C` | `ProcessSingleWorkItem` | `ProcessScannedItem` / `HandleScanResult` |
| 0xE | `0x8EF583` | `0x1808EF4A4` | `ThreatAnalysisWorkerThread` | `ThreatAnalysisWorker` / `ScanWorkerThread` |
| 0xF |  |  | `ntdll.dll` | `TppWorkerThread` |
| 0x10 |  |  | `ntdll.dll` | `TppWaipCallback` |
| 0x11 |  |  | `KERNEL32.DLL` | `BaseThreadInitThunk` |
| 0x12 |  |  | `ntdll.dll` | `RtlUserThreadStart` |


## idx 4: ScanMemoryLayout()

Detects **process hollowing**  a code injection technique where an attacker creates a suspended process, unmaps its memory, and replaces it with malicious code. The function scans the target p
rocess's memory layout to find regions that are **executable but not backed by a loaded image (DLL/EXE)**  the hallmark of injected code.


### 0: Pre-flight Checks

Three early-exit conditions prevent re-running the check:

| Check | Meaning |
|-------|---------|
| `DAT_1810ADE21 != 0` | Globally disabled via `MpDisableProcessHollowingChecks` registry flag |
| `+0x7B1 != 0` | Hollowing scan already completed for this process |
| `+0x7B2 != 0` | Hollowing already *detected* for this process |


### 1: Open Target Process

```
Call AcquireProcessHandleForScan(param_1 + 0x198, 0x410)
```

- **Access mask `0x410`** = `PROCESS_QUERY_INFORMATION` (0x400) | `PROCESS_VM_READ` (0x10)
- On x64 (detected via `FUN_180138584` reading TLS), this gets expanded with `0xC00` = `PROCESS_VM_READ` (0x10) | `PROCESS_VM_OPERATION` (0x8)

So on x64 the full mask is `0x410 | 0xC00` = `0xC10` = `PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION`.

This handle is stored in `*param_1` from `AcquireProcessHandleForScan`.


### 2: Memory Scanning

The function has **two scanning strategies**, selected by whether prior analysis data exists at offset `+0x7B8`:

#### Phase A: Entry Point Locator (`FUN_1802939BC`, when `+0x7B8 == 0`)

If no prior results are available, calls `FUN_1802939BC` which:

1. Calls `FUN_1802943B0` to get basic process info
2. Queries the process's main module size via `FUN_18088A460`
3. Walks memory via `VirtualQueryEx` looking for the **first executable region**
4. Returns its base address and size as the "expected" normal image memory for comparison later

If this returns error `299` (`0x12B`): logs telemetry and **skips hollowing check entirely**.

#### Phase B: Main Hollowing Detection Loop (when `+0x7B8 != 0`, or after Phase A)


The main loop iterates the process's address space via `VirtualQueryEx`. For each region:

```
while (accumulated_size < expected_size) {
    VirtualQueryEx(hProcess, lpAddress, &mbi, 0x30);

    // PROTECTION CHECK:
    // The bitmask 0x1000000010001 has bits set at positions 0, 16, 48
    // This accepts:
    //   PAGE_EXECUTE           (0x10)  (0x10-0x10) = 0   bit 0   matches
    //   PAGE_EXECUTE_READ      (0x20)  (0x20-0x10) = 16  bit 16  matches
    //   PAGE_EXECUTE_READWRITE (0x40)  (0x40-0x10) = 48  bit 48  matches
    //   PAGE_EXECUTE_WRITECOPY (0x80)                      explicit check

    if ((protection NOT in [0x10, 0x20, 0x40]) AND (protection != 0x80))
        break;  // Non-executable region  stop scanning

    // TYPE CHECK:
    if (mbi.Type != MEM_IMAGE (0x1000000)) {
        // ALERT: executable memory NOT backed by a file mapping
        Log "Hollow1" alert
        Set flag +0x7B2 = 1  (hollowing detected)
        break;
    }

    accumulated_size += mbi.RegionSize;
    lpAddress += mbi.RegionSize;
}
```

**Detection Logic:**
- If any memory region has **executable permissions** (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY) but is **NOT** of type `MEM_IMAGE`  **Process hollowing
detected**
- `MEM_IMAGE` (0x1000000) = memory mapped from an executable image section (normal loaded DLL/EXE).
- `MEM_PRIVATE` (0x20000) = privately allocated memory (VirtualAlloc)  this is what the check flags.
- The loop exits early as soon as a non-executable region is found (because image sections are contiguous in normal processes).


###  3: Alerting

When hollowing is detected:

```c
FUN_1806BA9EC(param_1, 0, L"Hollow1", 1);
// This is a telemetry/alert function that:
//  - Logs "IntegrityEnum: 1" (the hollowing type ID)
//  - Collects process metadata (PID, creation time, parent PID)
//  - Gathers loaded module information
//  - Sends to Windows Defender telemetry backend
```

The third parameter `1` (the `param_4` or "IntegrityEnum") means this is integrity level 1 (process hollowing detection).


### 4: Cleanup

```
CloseHandle(hProcess)
Zero out the handle struct
```


### Supporting Functions

| Function | Role |
|----------|------|
| `FUN_180293084` | Pre-scan setup: checks `+0x794` (enable scanning) and `+0x799` (already scanned) flags; may invoke telemetry if EoP changed |
| `FUN_180293174` | Post-scan teardown: checks for SeDebugPrivilege changes (EoP detection), reopens process handle if needed for privilege checking |
| `FUN_1802939BC` | Entry point locator  finds the first executable memory region in the target |



### Key Data Structures

| Offset | Type | Meaning |
|--------|------|---------|
| `+0x198` | struct | PID + creation time (passed to OpenProcess) |
| `+0x7B0` | byte | Process is "open" for scan? |
| `+0x7B1` | byte | Hollowing check completed |
| `+0x7B2` | byte | Hollowing detected |
| `+0x7B3` | byte | Post-scan teardown enabled |
| `+0x7B4` | byte | SeDebug privilege changed / EoP |
| `+0x7A8` | HANDLE | Saved process handle |
| `+0x7B8` | pointer | Prior memory scan results (entry point address) |
| `+0x7C0` | uint64 | Expected total image size |
| `+0x794` | byte | Scanning enabled flag |
| `+0x799` | byte | Scan already done flag |


### Summary

`CheckProcessHollowing` is Defender's adversarial memory integrity check. It opens the target process, walks its virtual address space, and identifies any region that is **executable but not file-backed**
  the defining characteristic of hollowed/injected code. The use of `PROCESS_VM_READ` (via `OpenProcess`) is what triggers the ETW event you captured in the stack trace.



## idx: 5 FinalizeScanResults()

`ProcessScanCleanup` is a **composite teardown & integrity check routine** that runs after each classification pass on a target process. It has two modes:

| `param_2` | Mode | What it does |
|-----------|------|-------------|
| `1, 3, 4, 5` | **Light cleanup** | Run hollowing check + SeDebug privilege check only |
| `2` | **Full reset** | Light cleanup + flush pending operations + reset all scan state flags |


### Flow

```
ProcessScanCleanup(param_1, param_2)

 1. FUN_180293084(param_1)           Pre-scan EoP integrity check

 2. CheckProcessHollowing(param_1)   Memory layout scan (OpenProcess trigger)

 3. FUN_180293174(param_1)           Post-scan SeDebug privilege check

 4. IF param_2 == 2 AND flag +0x7B0 is set:
     WaitForPendingOperations(param_1 + 0x2000)
     Reset flags: 0x799, 0x7B4, 0x7B2, 0x7B0  0
     CloseHandle(+0x7A8) and null it
     SignalPendingOperations(param_1 + 0x2000)
```



### 1: Pre-Scan EoP Integrity

Checks whether scanning is enabled (`+0x794`) and not yet completed (`+0x799`):

- If initial EoP level (`+0x7A0 & 0xF`) hasn't exceeded a threshold (`+0x728`), queries the current EoP level via `FUN_1802C13E0`  this checks whether the process has since elevated privileges
 (e.g., SeDebugPrivilege was acquired after initial scan).
- If a prior EoP value exists (`+0x798 == 1`), checks if integrity level increased; if so, fires telemetry alert via `FUN_1806BA9EC(param_1, new_level, "EopLevel", 0)`.

Essentially: **detects if the scanned process escalated privileges between scans.**


### 2:  Memory Integrity

The core hollowing detection (detailed in the previous answer). Opens the process with `PROCESS_VM_READ`, walks memory regions checking for executable-but-not-image-backed pages.


### 3: Post-Scan SeDebug Check

Only runs if `DAT_1810ADE22 == 0` (SeDebug checking not disabled) and `+0x7B3 != 0` (post-scan enabled) and `+0x7B4 == 0` (not already detected):

```
if (process_not_already_open) {
    AcquireProcessHandleForScan(param_1 + 0x198, 8, &hProcess);
}
Get SeDebug token status via FUN_180291EC8
if (status_changed) {
    if (old_status == 0)       Log "SeDebugEop"  (newly acquired)
    else if (old_status == -2)  Log "SeDebugEop1" (privilege revoked then re-acquired)
    Set flag +0x7B4 = 1
}
CloseHandle(hProcess)
```

This detects if the process has **enabled SeDebugPrivilege** (which grants full access to any process)  a strong indicator of malicious intent.


### 4: Full Reset

This path executes only for the final teardown. It performs a synchronized reset of the entire scan state:

**`FUN_1808E630C`  WaitForPendingOperations**
The structure at `+0x2000` is a synchronization object (critical section + counter + condition variable). This function:
1. Enters the critical section at `+0x2000`
2. Atomically adds `0x40000000` to a pending-operations counter (marks all in-flight operations as "wait for me")
3. Spins calling `FUN_1808E2070` (which waits on a condition variable via `Sleep` with exponential backoff) until the accumulated count of completed operations reaches or exceeds the new counter value
4. Leaves the critical section

This ensures **all concurrent scan operations finish before resetting state.**

**Flag Reset:**
```c
+0x799 = 0  // Reset "scan completed" flag
+0x7B4 = 0  // Reset "SeDebug EoP detected" flag
+0x7B2 = 0  // Reset "hollowing detected" flag
+0x7B0 = 0  // Reset "process open for scan" flag
CloseHandle(+0x7A8)  // Close tracked process handle
+0x7A8 = 0
```

**`FUN_1808E6484`  SignalPendingOperations**
1. Atomically removes `0x40000000` from the pending-operations counter
2. If waiters remain (those waiting for the full reset to complete), signals the condition variable via `FUN_1808E1EFC`
3. Leaves the critical section


### Scan State Flags

| Offset | Flag | Purpose |
|--------|------|---------|
| `+0x794` | Scanning enabled | Prevents scanning if not set |
| `+0x799` | Scan completed | Prevents re-scanning same process |
| `+0x7A0` | EoP level raw | Bits 0-3: initial integrity level |
| `+0x7A8` | Cached HANDLE | Process handle reused across checks |
| `+0x7B0` | Process accessed | Handle has been opened |
| `+0x7B1` | Hollowing checked | Hollowing scan already done |
| `+0x7B2` | Hollowing detected | Process hollowing found |
| `+0x7B3` | Post-scan enabled | Enable SeDebug privilege check |
| `+0x7B4` | SeDebug EoP | Privilege escalation detected |


### Summary

`ProcessScanCleanup` is the **safety net** that runs after every image load classification. In "light" mode it re-checks for process hollowing and privilege escalation. In "full reset" mode (`param_2 == 2
`), it additionally flushes all pending concurrent operations and completely resets the scan state, closing the process handle  preparing the scan context for potential reuse on the same proce
ss later.


## idx 6: ClassifyImageModule()

This is the **central classification dispatcher** for Windows Defender's Real-Time Protection. It receives an image load event and dispatches to the correct handler based on the **scan type** encoded in `
event_data[1].Flink`. Each handler evaluates the module through different trust/security lenses and logs results via ETW.


### Scan Type Dispatch

| Type | Name | What It Does |
|------|------|-------------|
| **1** | Initial Image Load | Friendly trust check, ASR rule evaluation, exclusion check |
| **2** | Module Unload / Teardown | Checks special state, runs full cleanup |
| **3** | Re-inspection | Re-evaluates code signing info after initial scan |
| **4** | Quick Cleanup | Only runs `ProcessScanCleanup` |
| **5** | Trust/Friendly Evaluation | Cache-based friendly lookup, slow trust check fallback |
| **6** | Running Module Load | Full ASR + signing evaluation for modules in running processes |
| **0x29** | Code Signing Trust | Parses and logs code signing certificate chain |
| **0x2D** | Verdict Logging | Formats and logs a structured verdict string |



### Type 1: Image Friendly

Initial Image Load (Friendly/Trust/ASR)

```
1. Get process info via FUN_1801DB51C(param_2, ...)
2. Get scan config via FUN_180294798(param_2, ...)
3. Resolve the module path/hash via FUN_180525F94
4. IF DAT_1810ADE62 == 0 (ASR enabled):
   a. Call FUN_1804B60B4(image_info, &results)  ASR rule evaluation
   b. For each ASR match found:
      - Log result via FUN_18063A9C8 (ETW event)
   c. If no match or specific conditions:
      - Log directly via FUN_18063A9C8
5. ELSE:
   - Log all matches with signing context
6. IF follow-up flag set:
   - Call FUN_18003A74C for follow-up tracking
7. ProcessScanCleanup(param_2, 1)  light cleanup
8. Dispatch callback to final handler
```

**Key operation:** Evaluates whether the newly loaded image violates ASR rules, checks signing, and either allows or flags it.


### Type 5: Friendly Evaluation

This is the most complex path and the most interesting for understanding Defender's trust model:

```
1. Enter critical section on param_2 + 0xA7 * 8 (process lock)
2. Get image/module path via FUN_180129D4C
3. Compare with existing path via FUN_1809D5140  skip if identical
4. Get cached trust result via global trust store:
   - EnterCriticalSection(DAT_1810BC1D0)
   - Acquire DAT_1810BC228 (trust LRU cache)
   - FUN_1800B58E4(cache, path, &result)  cached lookup
   - If miss: error 0x80004004
5. Check if module is "known" via FUN_1802B2164
6. If DAT_1810ADF19 == 0 (trust check not disabled):

   **Signer consistency check:**
   - Find '\\' in both old and new path via FUN_1809C9330
   - Compare prefix lengths and compare strings via FUN_1809DF630
   - If different: set "untrusted" marker (0x180C33EC8)

7. Determine trust context:

   a. Check scan scenario via Bm_GetCurrentScanScenario()
      - If not scenario 0 and flag allows: check image name lists
        via Bm_GetImageNameResolver  compare against known categories

   b. Set isSlowCheck flag for scenarios 1, 2, 3, 4, 6

8. Friendly cache lookup:

   a. IF new == old (same module):
      - Check MpUseNewFriendlyCacheKey feature flag
      - If new cache: compute hash via FUN_1808E1024(path)
      - If old: format key as "%ls%u%u%u" via FUN_1808E1808
      - Look up in friendly tree via FUN_1808F3300

   b. IF new != old:
      - Call FUN_18003CD04(path, 1, 1, flags)  alternate trust check

9. IF found in friendly cache:
   - Read cached result (byte at cache_entry + 0x28  local_306)
   - If result is trusted (local_306 == 0) and not excluded:
      local_308[0] = 0 (NOT suspicious)

10. IF isSlowCheck (scenario 1,2,3,4,6):
    - Format: "Module load (%ls) %ls trusted. IsFriendly:%u, IsExcluded:%u. ScanError: 0x%08lX."
    - Report ETW activity ID "31971010"

11. IF NOT trusted, no scan error, and no exclusion:
    a. Report to tracking system via FUN_18046DDD4
    b. Trigger re-inspection: Bm_ReinspectTrackedProcess(store, pid, 1)

12. IF all clear and scenario allows:
    - Clear follow-up tracking via FUN_18003A74C
    - ProcessScanCleanup(param_2, 5)
```

**Key decision:** Uses a cached friendly/trust database. If cached result says "trusted," skips deep scanning. If not cached or untrusted, triggers `Bm_ReinspectTrackedProcess` for deeper analysis.


### Type 6:  Running Module Load

Running Module Load (ASR Evaluation)

```
1. Get module info from metastore via FUN_180129A38
2. Get image name via Bm_GetImageNameConfigProvider
3. Look up config via FUN_18073B514
4. Check ASR rules:

   a. ASR Office Block Injection rule:
      If rule matched AND process blocked:
       "Friendly process '%ls' was blocked by ASR Office Block Injection rule"
       Suppress ASR notification

   b. ASR lsass rule:
      If rule matched:
       "Friendly process '%ls' was blocked by ASR lsass rule"
       Suppress ASR notification

   c. General ASR evaluation:
      - Get rule ID via FUN_1800EA464
      - Check block status via FUN_1804D0AA8
      - Call FUN_18043F9EC  full ASR evaluation
      - If high-severity: also send structured telemetry via FUN_18000A7B0
```


### Data Structures

Type 0x29  Code Signing Trust

```
1. Resolve signer path from event data
2. Set ETW event code: 0x409E
3. Log signing event via FUN_180120D80
4. Additional flags from param_3[0x20].Flink included in event
```

Type 0x2D  Verdict Formatting

```
1. Require non-null verdict string at param_3[0x18].Blink
2. Resolve path strings from param_3 offsets (signer, cdhash, teamid)
3. Format: "verdict:%d;codesigningflags:%u,signer:%s,cdhash:%s,teamid:%s"
4. Log via FUN_180120D80
```

### Shared Cleanup

Every scan type paths through `joined_r0x000180126639`:
1. Release acquired resources via `FUN_1805BBD30`
2. Release metadata store via `FUN_1800B4E40`
3. Return 0 (success)

### Key ETW Activity Codes

| local_1ce | Code | Meaning |
|-----------|------|---------|
| `0x4010` |  | Re-inspection event |
| `0x4011` |  | Initial image load event |
| `0x4014` |  | Trust/friendly evaluation |
| `0x402B` |  | Module load event |
| `0x402C` |  | Extended module load event |
| `0x409E` |  | Code signing trust event |
| `0x40A5` |  | Verdict log event |

The ETW activity ID `"31971010"` is **the specific activity GUID used for logging friendly/trust evaluation results**  this is likely what you'd see in an EDR/ETW consumer when Defender determ
ines a module is (or isn't) trusted.