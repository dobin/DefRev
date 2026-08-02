# ClassifyProcessModuleNotification

At a high level, `ClassifyProcessModuleNotification` is the behavior-specific handler for module/image-related process notifications. It takes an internal Defender process context plus a process/module notification object and turns that into classification side effects: behavior events, trust checks, tainting, ASR notifications, reinspection, and cleanup.

Conceptually it works like this:

1. It identifies the notification subtype.

The important switch value is pulled from the notification object, roughly:

```c
eventType = notification->type;
```

It handles module/process notification types such as:

- `1`: process/image start style module event
- `3`: module load / image path event
- `5`: suspicious or changed module path / trust classification path
- `6`: ASR / injection-related module behavior
- `0x29`: special module behavior event
- `0x2d`: code-signing / notarization style metadata event
- `2`, `4`: cleanup / deferred process state updates

Unknown or unsupported types return an error-ish status.

2. It resolves useful names for the event.

A large amount of the function is path normalization and enrichment:

- Resolve NT paths to DOS paths.
- Resolve cached global path aliases.
- Remove duplicate path separators.
- Resolve process primary image path.
- Resolve module image path.
- Enumerate hardlink names when enabled.
- Emit alternate image name events.
- Compare module path against primary process image path in some cases.

This is why the function is so large: much of it is not “classification” in the ML sense, but producing canonical and alternate path representations for later behavior/reporting logic.

3. It emits behavior/module events.

For recognized module events, it builds a small event descriptor and emits one or more behavior events through helpers like:

- `EmitBehaviorModuleEvent`
- `EmitModuleEventWithOptionalAlias`
- `EmitModuleEventForHardlinkAlias`
- `EmitAlternateImageNameEvents`

These appear to map internal process/module notifications into Defender behavior telemetry or behavior-monitoring records.

4. It performs trust/friendly/exclusion checks.

For type `5` especially, it performs logic around whether a loaded or referenced module is trusted/friendly/excluded:

- Checks excluded-file cache.
- Runs friendly-file lookup or slow check.
- Uses cached friendly results if available.
- Emits debug/diagnostic output about whether the module is trusted.
- If the module is not trusted and no scan error occurred, it can mark the process as tainted.

This path can lead to:

```c
MarkProcessTaintedAndNotify(...)
Bm_ReinspectTrackedProcess(...)
```

So this function can directly affect Defender’s state for the process, not just emit telemetry.

5. It handles ASR/injection-style behavior.

For type `6`, it resolves the target process/module path and builds ASR-related context:

- target image path
- command line
- integrity level
- process identity
- ASR rule state
- suppression conditions for friendly/tainted processes

Then it may emit an ASR notification through something like:

```c
EmitAsrNotification(...)
```

There is also suppression logic for cases where Defender decides not to emit/block because the process is considered friendly or the rule state says not to.

6. It updates process bookkeeping.

Several branches call helpers like:

- `ProcessScanCleanupChecks`
- `TrackRecentlyTouchedPath`
- `ReportParentPropagationMatches`
- `UpdateParentPropagationProcessId`
- `UpdateDeferredProcessPathState`

So it also keeps the process context consistent after each module notification.

In short: `ClassifyProcessModuleNotification` is the module-notification classifier/enricher. It receives an already-routed internal notification, resolves paths and aliases, maps it to behavior events, performs trust/friendly/exclusion decisions, may taint or reinspect the process, and handles ASR/injection-related reporting. It is much more than a dispatcher; it is one of the main semantic handlers for process module behavior.


## EmitBehaviorModuleEvent

`ClassifyProcessModuleNotification` emits `EmitBehaviorModuleEvent` when a recognized module-related notification has been normalized into a behavior-module record. The trigger is mostly the notification subtype.

Direct/semantic emit cases:

| Notification subtype | Behavior event id | When emitted |
|---|---:|---|
| `1` | `0x4011` | Process/startup image module event after resolving process image path and snapshotting process context. Usually emitted through `EmitModuleEventWithOptionalAlias`, which wraps `EmitBehaviorModuleEvent`. |
| `3` | `0x4010` | Module/image path event after resolving the module path to a DOS/global-cache path. May emit once for normalized path and once for duplicate-separator-cleaned alias. |
| `5` | `0x4014` | Module path/trust classification path, when the module path is not just the primary process image and is not suppressed by exclusion logic. May emit for hardlink aliases or direct path depending config. |
| `6` | `0x402b` | Injection/ASR-style module behavior after resolving tracked process/image path and checking exclusion state. |
| `6` | `0x402c` | Additional companion event when a flag byte in the subtype-6 notification is set. |
| `0x29` | `0x409e` | Special module behavior event after resolving the supplied module path. Includes an extra DWORD from the notification payload. |
| `0x2d` | `0x40a5` | Code-signing/verdict metadata event, only if the notification has its “valid/present” byte set and the formatted metadata string is built successfully. |

It does not emit for every queued process notification. Subtypes `2` and `4` mostly do cleanup/deferred state handling, and unknown subtypes return failure without emitting.

Also, some emissions are indirect:

- `EmitModuleEventWithOptionalAlias(...)` calls `EmitBehaviorModuleEvent(...)`.
- `EmitModuleEventForHardlinkAlias(...)` calls `EmitBehaviorModuleEvent(...)`.
- `EmitAlternateImageNameEvents(...)` can call `EmitBehaviorModuleEvent(...)` for alternate image names.

So the practical answer is: it emits after path resolution/enrichment, when the notification subtype maps to a module behavior report and the event is not filtered out by path/exclusion/config checks.

And, in short: EmitBehaviorModuleEvent data is derived from INotification and may originate from ETW, but it is not itself the raw ETW event or a BM_Etw_* record. It is a normalized behavior-module event representation used by Defender’s behavior classification/rule engine.