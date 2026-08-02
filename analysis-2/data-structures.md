# Data Structures

```text
INotification = envelope / queue object
BM_Etw_*      = payload / behavior ID inside that envelope
```

So the connection is:

```text
Raw ETW event
 -> decoded into BM_Etw_* behavior payload
 -> wrapped into an EtwEvent INotification
 -> queued on ProcessContext
 -> worker pops the INotification
 -> callback extracts/uses the embedded BM_Etw_* behavior payload
```

Example:

```text
Raw Threat-Intelligence ProtectVm ETW
 -> BmEtw_HandleProtectVmCodeInjectionEvent
 -> BmEtw_EmitBehaviorEvent(
      0x402e,                 // BM_Etw_CodeInjection
      target image/name,
      "protectvm",
      extra fields
    )
 -> BmEtw_QueueBehaviorEventNotification
 -> EtwEvent INotification, tag 0x26
```

Then later:

```text
ProcessScanQueue pops INotification
 -> AnalyzeImageLoadEvent
 -> InvokeModuleScanCallbacks
 -> BmBehaviorCallbackThunk
 -> BmDispatchBehaviorEvent reads behavior id 0x402e from the payload
 -> BmHandleEtwCodeInjectionEvent
```

So to your specific questions:

- Are `BM_Etw_*` events translated into `EtwEvent`s?
  Yes, roughly. More precisely: the `BM_Etw_*` payload is wrapped into an `EtwEvent` `INotification`.

- Are they just attached to `INotification`?
  Yes. That is the best mental model. `EtwEvent` is the notification subtype; `BM_Etw_CodeInjection`, `BM_Etw_OpenProcess`, etc. are payload IDs/details inside it.

- Are they converted again into more generic behavior events?
  Sometimes downstream. The first conversion is `raw ETW -> BM_Etw_*`. Later, handlers like `BmHandleEtwCodeInjectionEvent` may emit richer or secondary behavior/module reports, e.g. `BM_Etw_CodeInjection` can become a richer V2 code-injection report. But the queued object is still initially an `EtwEvent` notification carrying the original `BM_Etw_*` payload.

Compact version:

```text
BM_Etw_* is not a queue object.
EtwEvent INotification is the queue object.
BM_Etw_* lives inside EtwEvent.
BmDispatchBehaviorEvent switches on the BM_Etw_* behavior ID.
```