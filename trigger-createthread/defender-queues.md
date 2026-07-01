# Defender Queue And Work-Item Flow

The execution chain has two queue layers:

1. Global simple threadpool queue
2. Per-process Behavior Monitoring notification queue

The worker-thread frames process the global threadpool queue. The actual module/process scan notifications are stored in the per-process Behavior Monitoring queue and are drained later by `ProcessScanQueue`.

## 1. Global Threadpool Work Item

Worker thread path:

```text
ThreatAnalysisWorkerThread
  -> DequeueNextSimpleThreadPoolWorkItem
  -> ProcessSingleWorkItem
  -> work_item->callback()
  -> work_item->release()
```

In this stack, the callback is:

```text
ScanItemWaitAndDispatch
  -> ProcessScanQueue
```

### Generic Work Item Layout

The item popped by `ThreatAnalysisWorkerThread` is a generic async work item.

| Offset | Field | Meaning |
|---:|---|---|
| `+0x00` | list link | Intrusive queue link. |
| `+0x08` | list link | Intrusive queue link. |
| `+0x10` | callback / execute function | Called by `ProcessSingleWorkItem`. For this chain, points to `ScanItemWaitAndDispatch`. |
| `+0x18` | release / cleanup function | Called after execution. |
| later fields | item-specific payload | For the BM notification item, includes process-context pointer. |

The work queue has three internal lists:

| Queue bucket | Selection |
|---|---|
| default list | Normal work items. |
| type `1` list | Special/priority bucket. |
| type `9` list | Another special bucket. |

The pop order in `DequeueNextSimpleThreadPoolWorkItem` is:

1. type `9` list
2. default list
3. type `1` list

### Threadpool Enqueue Function

The actual enqueue helper is:

```text
EnqueueSimpleThreadPoolWorkItem
```

What it does:

- Takes a work item.
- Inserts it into one of the three work lists.
- Increments queued-work count.
- If below max active worker count, wakes/submits worker execution.
- Worker later calls `ThreatAnalysisWorkerThread`.

Related threadpool helpers:

| Function | Purpose |
|---|---|
| `EnqueueSimpleThreadPoolWorkItem` | Pushes generic async work item into the simple threadpool. |
| `DequeueNextSimpleThreadPoolWorkItem` | Pops next work item from priority/default queues. |
| `ThreatAnalysisWorkerThread` | Worker-loop body. |
| `ProcessSingleWorkItem` | Calls the work item's execute callback and cleanup callback. |
| `ScanItemWaitAndDispatch` | Concrete work-item callback that drains the BM process queue. |
| `SubmitAsyncWorkItemToGlobalPool` | Wrapper used to submit the created notification work item to the global pool. |

## 2. BM Notification Work Item

The work item submitted to the global pool is created here:

```text
CreateNotificationWorkItemForProcessContext
```

This creates a `NotificationItem` object.

### `NotificationItem` Layout

| Offset | Field | Meaning |
|---:|---|---|
| `+0x00` | vtable | `NotificationItem::vftable`. |
| `+0x08` | refcount | Reference count. |
| `+0x10` | embedded async item / list node | Passed to the global async work pool. |
| `+0x18` | embedded async item / list node | Intrusive queue link / work-item state. |
| `+0x20` | execute callback | Set through the embedded async item setup. |
| `+0x28` | cleanup callback | Set through the embedded async item setup. |
| `+0x30` | async item state | Initialized by helper. |
| `+0x38` | process context pointer | Points to the BM per-process context. |
| `+0x40` | completion/ran flag | Set by `ScanItemWaitAndDispatch` after processing. |

Operationally:

```text
NotificationItem
  -> global work callback
  -> ScanItemWaitAndDispatch
  -> ProcessScanQueue(process_context)
```

The global threadpool item does not directly contain the module/process event. It contains a pointer to the process context, and that process context owns the real notification queue.

## 3. Per-Process BM Notification Queue

The real scan items are notifications stored in the process context.

The push function is:

```text
ProcessContextPushNotification
```

This is the key producer-side function.

### What The Per-Process Notification Contains

A notification is a polymorphic object. The exact concrete layout depends on the notification type, but `ProcessScanQueue` consistently uses these vtable slots:

| Vtable slot / behavior | Meaning |
|---|---|
| get notification type | Returns values like `1`, `2`, `3`, `5`, `6`, `0x29`, `0x2d`. |
| get PID/version tuple | Used to associate notification with the correct process context. |
| get priority/timestamp | Used for heap ordering in the process queue. |
| filtering predicates | Used to decide whether to drop, delay, propagate, or process. |
| type-specific fields | Module path, image path, signing data, ASR rule data, command line, target PID, etc. |

The queue itself is a priority heap/vector at the process context:

| Process context field | Meaning |
|---:|---|
| `+0x48` | heap/vector start for queued notifications. |
| `+0x50` | heap/vector end. |
| `+0x58` | heap/vector capacity. |
| `+0x74` / `+0x78` | queue limits / thresholds. |
| `+0x80` | queue lock. |
| `+0xf0` | dispatch lock used by `ProcessScanQueue`. |

`ProcessContextPushNotification` does these things:

- Checks whether the process context queue is stopped.
- Checks whether the process is excluded and whether the notification is skippable.
- Updates per-notification-type counters.
- Checks queue capacity.
- Inserts the notification into the priority heap.
- Creates a `NotificationItem` for the process context.
- Submits that `NotificationItem` to the global threadpool through `SubmitAsyncWorkItemToGlobalPool`.

## 4. Who Pushes Work Items Into The Queue

### Direct Producer

```text
ProcessContextPushNotification
```

Direct callers:

| Caller | Role |
|---|---|
| `SubmitNotificationToProcessContext` | Finds the correct process context for a notification, prepares path/process metadata, then pushes it. |
| `PropagateNotificationToRelatedProcesses` | Pushes a notification into related process contexts. |
| `BroadcastNotificationToActiveProcessContexts` | Broadcasts a notification to multiple active process contexts. |

### Queue Controller Layer

```text
QueueBmNotification
```

This is the main queue-controller entry point.

It does:

- Checks performance exclusion list.
- Calls notification factory to create one or more notification objects.
- Ensures process context exists.
- Calls `SubmitNotificationToProcessContext`.

Callers:

| Caller | Source category |
|---|---|
| `QueueRtpNotification` | Main RTP/BM notification queue path. |
| `QueueExtendedRtpNotification` | Alternate/extended notification input layout. |

### Upstream Notification Adapters

These are domain adapters that accept different notification domains and forward into the BM queue path.

| Function | Domain / category | Behavior |
|---|---:|---|
| `FUN_180122690` | domain `1` | Validates domain, then forwards to `QueueRtpNotification`. |
| `FUN_180123120` | domain `2` | Runs extra callbacks, then forwards to `QueueRtpNotification`. Likely process lifecycle / termination-related domain. |
| `FUN_1806163d0` | domain `8` | Validates domain, then forwards to `QueueRtpNotification`. |
| `FUN_1805eeab0` | domain `9` | Validates domain, then forwards to `QueueRtpNotification`. |
| `FUN_180a6c4a0` | extended input path | Uses metastore/controller, then calls `QueueExtendedRtpNotification`. |
| `HandlePropagationBehaviorReport` | propagation report path | Can call `BroadcastNotificationToActiveProcessContexts` for propagation-parent events. |

## 5. `ProcessScanQueue` Dispatch Subsystems

`ProcessScanQueue` drains the per-process notification queue and routes notifications into several subsystems.

### Dispatch Overview

| Notification condition | Destination subsystem |
|---|---|
| Type `1` | Startup/process/module-load tracking; can be delayed until process context is initialized. |
| Type `2` | Termination/deferred cleanup path; can be held separately and processed after earlier events. |
| Type `3`, `5`, `6`, `0x29`, `0x2d` | Main image/module behavior path via `AnalyzeImageLoadEvent`. |
| Type `0x2d` | Code-signing verdict path. |
| Predicate `FUN_180681050` true, type field `0x23` | Deferred list at process context `+0xa30`; processed after initialization. |
| Queue not initialized / `a18 & 0x10` not set | Initializes process state first, then replays delayed events. |
| Tainted or related-process state set | Can propagate notification to related process contexts. |

### Subsystems Reached From `ProcessScanQueue`

| Subsystem | Function path |
|---|---|
| Module/classification pipeline | `AnalyzeImageLoadEvent` -> `InvokeModuleScanCallbacks` -> `ClassifyImageModuleEvent`. |
| Related-process propagation | `PropagateNotificationToRelatedProcesses`. |
| Deferred process-state update | `UpdateDeferredProcessPathState`. |
| Process context initialization | `FUN_1801d9fd8` path, then delayed event replay. |
| Parent/propagation tracking | `ReportParentPropagationMatches`, `UpdateParentPropagationProcessId`. |
| Cleanup checks | `ProcessScanCleanupChecks` through the module classification path. |
| Hollowing / SeDebug / integrity checks | Reached later through `ProcessScanCleanupChecks`. |

## 6. Chronological Queue Flow

```text
External BM/RTP event arrives
  -> domain adapter validates event domain
  -> QueueRtpNotification / QueueExtendedRtpNotification
  -> QueueBmNotification
  -> SubmitNotificationToProcessContext
  -> ProcessContextPushNotification
       - inserts notification into per-process priority heap
       - creates NotificationItem for process context
       - submits NotificationItem to global simple threadpool
  -> EnqueueSimpleThreadPoolWorkItem
  -> ThreatAnalysisWorkerThread
  -> ProcessSingleWorkItem
  -> ScanItemWaitAndDispatch
  -> ProcessScanQueue
  -> AnalyzeImageLoadEvent / propagation / deferred handling
  -> ClassifyImageModuleEvent and cleanup checks
```

In short: notifications are pushed by `ProcessContextPushNotification`, usually through `QueueBmNotification` and `SubmitNotificationToProcessContext`; the worker thread only wakes up a process-context drain item, and `ProcessScanQueue` performs the real notification dispatch.
