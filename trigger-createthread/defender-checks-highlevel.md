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
