Mapped `mpengine.dll` runtime base `0x7ffeefb40000` to Ghidra image base `0x180000000`.

| idx | address | module | rebased / offset | function name |
|---:|---|---|---|---|
| 0x0 | `0x7fff078112c4` | `ntdll.dll` | n/a | unresolved |
| 0x1 | `0x7fff04dd246e` | `KERNELBASE.dll` | n/a | unresolved |
| 0x2 | `0x7ffeefc783ce` | `mpengine.dll` | `+0x1383ce` / `0x1801383ce` | `OpenProcessWithAccess` |
| 0x3 | `0x7ffeefc781c7` | `mpengine.dll` | `+0x1381c7` / `0x1801381c7` | `AcquireProcessHandleForScan` |
| 0x4 | `0x7ffeefdd33d7` | `mpengine.dll` | `+0x2933d7` / `0x1802933d7` | `CheckProcessHollowing` |
| 0x5 | `0x7ffeefdd3010` | `mpengine.dll` | `+0x293010` / `0x180293010` | `ProcessScanCleanupChecks` |
| 0x6 | `0x7ffeefc66c8e` | `mpengine.dll` | `+0x126c8e` / `0x180126c8e` | `ClassifyProcessModuleNotification` |
| 0x7 | `0x7ffeefc65ae0` | `mpengine.dll` | `+0x125ae0` / `0x180125ae0` | `ModuleTrustCallbackThunk` |
| 0x8 | `0x7ffeefc65911` | `mpengine.dll` | `+0x125911` / `0x180125911` | `ProcessNotificationCallbackRouter` |
| 0x9 | `0x7ffeefc6512c` | `mpengine.dll` | `+0x12512c` / `0x18012512c` | `InvokeProcessNotificationCallbacks` |
| 0xa | `0x7ffeefc64fd6` | `mpengine.dll` | `+0x124fd6` / `0x180124fd6` | `AnalyzeQueuedProcessNotification` |
| 0xb | `0x7ffeefc648d5` | `mpengine.dll` | `+0x1248d5` / `0x1801248d5` | `ProcessScanQueue` |
| 0xc | `0x7ffeefc64694` | `mpengine.dll` | `+0x124694` / `0x180124694` | `ScanItemWaitAndDispatch` |
| 0xd | `0x7ffef042f698` | `mpengine.dll` | `+0x8ef698` / `0x1808ef698` | `ProcessSingleWorkItem` |
| 0xe | `0x7ffef042f583` | `mpengine.dll` | `+0x8ef583` / `0x1808ef583` | `ThreatAnalysisWorkerThread` |
| 0xf | `0x7fff077d28ea` | `ntdll.dll` | n/a | unresolved |
| 0x10 | `0x7fff077a5eb6` | `ntdll.dll` | n/a | unresolved |
| 0x11 | `0x7fff05b6259d` | `KERNEL32.DLL` | n/a | likely `BaseThreadInitThunk` |
| 0x12 | `0x7fff077caf78` | `ntdll.dll` | n/a | likely `RtlUserThreadStart` |