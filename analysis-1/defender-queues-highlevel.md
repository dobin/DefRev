# Defender Queue Flow: High-Level Summary

1. **External Event Arrives**

   - Defender receives a behavior-monitoring event from RTP/BM telemetry.
   - The event may describe process start, process termination, module load, signing verdict, ASR-related activity, or propagation state.
   - A domain-specific adapter validates the event category before it enters the queueing pipeline.

2. **Notification Object Is Created**

   - Defender converts the raw event into one or more internal notification objects.
   - Each notification carries the event type, process identity, timing/priority data, and type-specific metadata.
   - Type-specific metadata can include module path, image path, signing information, command line, ASR rule context, or target process details.

3. **Target Process Context Is Resolved**

   - Defender identifies which tracked process context should receive the notification.
   - It validates the process identity using PID/version-style data.
   - If no suitable process context exists, the notification can be dropped, logged, or used to create/update tracking state.

4. **Notification Is Pushed Into The Per-Process Queue**

   - Defender inserts the notification into that process context’s internal priority queue.
   - The per-process queue is ordered by notification priority or timestamp.
   - Queue limits are checked before insertion.
   - Excluded or skippable notifications can be dropped before they reach later scan stages.

5. **Drain Work Item Is Created**

   - After pushing the notification, Defender creates a lightweight work item for the process context.
   - This work item does not contain the full scan event itself.
   - It mainly points back to the process context whose notification queue needs draining.

6. **Work Item Enters The Global Threadpool Queue**

   - The drain work item is submitted to Defender’s global simple threadpool.
   - The global queue has multiple priority buckets.
   - The worker thread later picks up the item and runs its callback.

7. **Worker Thread Dispatches The Drain Item**

   - A worker thread pops the next work item from the global queue.
   - It calls the work item’s execute callback.
   - For this chain, that callback is the process-queue drain routine.

8. **Per-Process Queue Is Drained**

   - The drain callback wakes the process context and begins processing queued notifications.
   - Defender pops notifications from the per-process priority queue.
   - Some notifications may be delayed until process initialization or required metadata is ready.
   - Deferred notifications are replayed once the process context becomes ready.

9. **Notification Is Routed By Type**

   - Each notification is dispatched based on its type.
   - Module-load and image events go to the module classification pipeline.
   - Termination events go to cleanup/deferred-state handling.
   - Signing verdict events go to code-signing/reporting logic.
   - Propagation events can be forwarded to related process contexts.

10. **Subsystem-Specific Processing Runs**

    - The selected subsystem performs its checks.
    - Module events can trigger trust, friendly-file, hardlink, signing, and ASR checks.
    - Cleanup paths can trigger hollowing, integrity, and SeDebug checks.
    - Propagation paths can enqueue follow-up notifications for related processes.

11. **Follow-Up Notifications May Be Requeued**

    - Some results cause Defender to push additional notifications.
    - Examples include related-process propagation, deferred event replay, or process reinspection.
    - These follow-up notifications re-enter the same per-process queue and threadpool flow.

12. **Work Item Completes**

    - After the process queue is drained or paused, the worker releases the work item.
    - Queue state and completion flags are updated.
    - The process context remains available for future notifications.
