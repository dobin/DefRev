# DefRev - CreateRemoteThread() Trigger for OpenProcess()

* GPT 5.5 high
* ~40$
* https://winbindex.m417z.com/?file=mpengine.dll


## A Trigger Callstack

The input, the base of this analysis. 
A Defender OpenProcess ETW callstack triggered by `CreateRemoteProcess()`. 

* [defender-trigger.md](defender-trigger.md)

Analysis result, topics: 
* Queue -> Process Scan -> OpenProcess()


## B Callstack details

* [defender-callstack.md](defender-callstack.md)

The callstack analysis shows that the following three functions are mostly
involved in performing a process scan:

* Index 0: ntdll.dll
* Index 4: `ScanMemoryLayout()` (misname as `CheckProcessHollowing()`)
* Index 5: `FinalizeScanResults()`  (misnamed, more like `DoMemoryLayoutScan()`)
* Index 6: `ClassifyImageLoadEvent()`  (2000+ lines large, main scan function)

It triggered because it found a unbacked memory region, which made Defender
open the target process with READ_VM rights, as identified by the ETW event
`PspLogAUditOpenProcessEvent` this callstack is based on. 

Analysis topic: 
* Queue -> **Process Scan -> Find unbacked memory images** -> OpenProcess()


## C Other Checks

Details of the functions involving in the detection of the unbacked memory image above. 
This is the parent of the 

What other memory related does defender perform?

* [defender-checks.md](defender-checks.md)
* [defender-checks-highlevel.md](defender-checks-highlevel.md)

Analysis topic: 
* Queue -> **Process Scan** -> ...


## D Queue Management

Defender 

* [defender-queues.md](defender-queues.md)
* [defender-queues-highlevel.md](defender-queues-highlevel.md)

Analysis topic: 
* Functions -> **Queue -> More Queue** -> Process Scan -> ...


# E Queue Input


* [defender-queues-input.md](defender-queues-input.md)

Analysis topic: 
* **Input** -> Queue -> More Queue -> Process Scan ->



