# BM_MetaStore

`BM_MetaStore` is best understood as Defender BM’s shared state and correlation layer, not just an event sink.

There are two related things in the binary:

- `Bm_GetMetaStore` returns a global refcounted BM service object at `DAT_1810baef8`. Ghidra shows this object being constructed with `BmController::vftable`, so the public name is a little misleading.
- A separate `MetaStore::...::MetaStore` object backs durable storage through `MetaVaultStorageSQLite` and typed `MetaVaultRecord*` records.

**High-Level Purpose**
`BM_MetaStore` functions as a BM blackboard:

- Stores process/file/network/security metadata for later correlation.
- Maintains live caches for process identity, image path, verdict/friendly/excluded state, and counters.
- Wraps durable SQLite-backed “MetaVault” records with typed logical stores.
- Lets BM components query “what do we already know about this process/file/action?”
- Provides suppression/dedup/friendly verdicts before reporting behavior.
- Bridges raw ETW/BM notifications into process-context-aware state.

**Singleton / Lifetime**
`Bm_GetMetaStore`:

```c
EnterCriticalSection(&DAT_1810baea0);
if (DAT_1810baef8 == 0) return 0x80004004;
AddRef(DAT_1810baef8);
*out = DAT_1810baef8;
```

Created by `FUN_18086b418`, destroyed/released by `FUN_180afe37c`.

So yes, there is a singleton-like global object, but it is refcounted and guarded by a critical section.

**Durable MetaVault Layer**
The actual persistent store is initialized by:

- `FUN_180af6d5c`
- `FUN_180af4b7c`
- `FUN_180af5acc`
- `FUN_180af4f20`

It registers settings such as:

- `MpMetaStoreDisable`
- `MpMetaStoreReadOnly`
- `MpMetaVaultSize`
- `MpMetaVaultRecordExpiration`
- `MpMetaVaultMaintenanceInterval`
- `MpMetaVaultBmProcessInfoSize`
- `MpMetaVaultFileHashesSize`
- `MpMetaVaultAnomalySize`
- `MpMetaVaultAmsiFileCacheSize`

Typed vaults include:

- `BmProcessInfo`
- `BackupProcessInfo`
- `BmFileInfo`
- `FileHashes`
- `ProcessBlockHistory`
- `Anomaly`
- `AttributeCounts`
- `AttributePersistContext`
- `AmsiFileCache`
- `Network`
- `NetworkIpFirewallRules`
- `RollingQueues`
- `AtomicCounters`
- `BootSectors`
- `FolderGuardPaths`
- `SdnEx`
- `DynSigRevisions`
- `Database`

This is a structured SQLite-backed state store, not a flat event log.

**Main Usage Patterns**
`Bm_MetaStoreLookupVerdict` is one of the most important APIs.

It takes a stable process/image key, checks:

- live `ProcessContext` map,
- in-memory verdict cache,
- resolved image path,
- persisted/friendly verdict logic,

then returns verdict flags used to suppress or mark events.

Used by:

- `Bm_EvaluateProcess`
- `ReportRemoteThreadInjectionBehavior`
- file/module/process classification paths

Example behavior:

- If a target process is already known as friendly/excluded, remote-thread/code-injection behavior may be suppressed.
- If a process image verdict is cached, BM avoids expensive path/signature checks.
- If not cached, it resolves image path, computes verdict, then stores result.

`Bm_MetaStoreRecordEvent` is also notable. It does not simply append an event. It:

1. Extracts the process identity from the event.
2. Looks up the live `ProcessContext`.
3. Updates that context via `FUN_1803cc268`.

`FUN_1803cc268` classifies stored event records into types like:

- `Registry`
- `Injection`
- `ProcessCreate`

Then queries metastore records and attaches correlated data back to the process context.

**ETW Relationship**
The ETW callback path uses metastore early:

- `FUN_180129840` calls `Bm_GetMetaStore`.
- It invokes an ETW sink object reachable from the returned BM/metastore object.
- Raw ETW is decoded/classified, then normalized into BM events.
- Later, metastore verdicts decide whether those events should be reported, suppressed, enriched, or correlated.

**Mental Model**
Think of `BM_MetaStore` as three things combined:

1. **Live BM state manager**: process contexts, counters, verdict cache, event routing.
2. **Correlation database**: durable typed records for process/file/network/anomaly history.
3. **Policy/verdict cache**: friendly/excluded/process-action decisions reused by ETW, module, process, and file behavior paths.

Your assumption is mostly right: suspicious findings and metadata are placed there for later correlation. But it is broader than just suspicious findings. It stores benign/friendly verdicts, process identity history, file metadata, throttling/counters, network state, AMSI cache, and BM operational state too.


# Sqlite DB

Yes, it is file-backed SQLite.

Confirmed strings:

- `mpenginedb.db`
- `mpenginedb.db-wal`
- `mpenginedb.db-shm`
- `mpenginedb.db-journal`
- `SQLiteGlobals`
- `MetaVaultStorageSQLite::Insert`
- `MetaVaultStorageSQLite::Query`
- `MetaVaultStorageSQLite::Maintenance`

The DB path is constructed as:

```text
<Defender engine/base directory>\mpenginedb.db
```



The base directory comes from Defender global config at `DAT_1810c5310 + 0x6a8`. The same base is used for engine/sandbox files like `MsMpEngCP.exe` / `MsMpEngSvc.dll`, so on a live Windows system it is likely under Defender’s protected engine/platform data area.

**Important caveats**

- It likely uses WAL mode, so copy all sidecars:
  - `mpenginedb.db`
  - `mpenginedb.db-wal`
  - `mpenginedb.db-shm`
  - `mpenginedb.db-journal`, if present
- It may be ACL-protected and locked by Defender.
- There is a setting `MpSqliteCodecDisable`, suggesting encryption/codec support may exist. If codec is enabled, a raw copy may not open cleanly with stock `sqlite3`.
- Some state is only in live in-memory caches/process contexts, so the DB is not a complete dump of all BM state.


## Directory

`C:\ProgramData\Microsoft\Windows Defender\Scans\`:
```
drwxr-xr-x 2 root root     4096 Jul  6 16:12 BackupStore
drwxr-xr-x 2 root root     4096 Jul  6 16:12 CleanFileTelemetry
-rwxr-xr-x 1 root root  2117664 Jul  6 16:12 DefenderEcsCache.bin64
drwxr-xr-x 2 root root     4096 Jul  6 16:12 FilesStash
drwxr-xr-x 7 root root     4096 Jul  6 16:12 History
-rwxr-xr-x 1 root root 35767028 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin
-rwxr-xr-x 1 root root  1449336 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.01
-rwxr-xr-x 1 root root 52479192 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.67
-rwxr-xr-x 1 root root  3500608 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.6C
-rwxr-xr-x 1 root root 63451136 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.79
-rwxr-xr-x 1 root root  8474624 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.7C
-rwxr-xr-x 1 root root 59900192 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.7E
-rwxr-xr-x 1 root root 26210612 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.80
-rwxr-xr-x 1 root root  2028520 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.83
-rwxr-xr-x 1 root root 12489284 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.87
-rwxr-xr-x 1 root root   438272 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.91
-rwxr-xr-x 1 root root   438272 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.9C
-rwxr-xr-x 1 root root 44237984 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.A0
-rwxr-xr-x 1 root root  1127696 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.DB
-rwxr-xr-x 1 root root    69336 Jul  6 16:12 mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.E6
-rwxr-xr-x 1 root root      120 Jul  6 16:12 MpDiag.bin
-rwxr-xr-x 1 root root   512000 Jul  6 16:22 mpenginedb.db
-rwxr-xr-x 1 root root    24192 Jul  6 16:12 MsMpEngCP.exe
-rwxr-xr-x 1 root root    55200 Jul  6 16:12 MsMpEngSvc.dll
drwxr-xr-x 3 root root     4096 Jul  6 16:12 RtSigs
```

```
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.87
./History
./History/Service
./History/Service/Unknown.Log
./History/Service/History.Log
./History/Results
./History/Results/Resource
./History/Results/Resource/{DAB3D98E-E8B0-4472-8EF9-C8C48F2B0805}
./History/Results/Resource/{E0DED3AC-0A79-4FC1-A045-44A6C16DFBCB}
./History/Results/Resource/{0F8ACD10-0478-4F6A-AE5F-43FBBEF4C86E}
./History/Results/Resource/{409EAAAE-9014-4B2D-B836-F94C6C0723C7}
./History/Results/Resource/{D58AFF6E-C86E-43D4-888D-B0023A281361}
./History/Results/Resource/{A09C49A5-5FD2-4D57-A9FC-CCB5A8D4A2A9}
./History/Results/Resource/{C0F8E9B5-89EC-44D1-9C84-8B6FF7B3754C}
./History/Results/Resource/{384A8842-CD9E-400C-9226-8C0D103FC9A7}
./History/Results/Resource/{82E198CE-5E10-4D78-8970-F9EA123433C0}
./History/Results/Resource/{2B61CB76-3D7F-4806-AC4B-813CF7AC6B8A}
./History/Results/Resource/{06A3EB7C-FB0D-40AE-AC4D-19B2F480DFBB}
./History/Results/Resource/{73F71983-09EB-4215-AFF1-8ABC0C6BEDD1}
./History/Results/Resource/{39E72FED-359D-4495-A1DD-FB87A57F3FFB}
./History/Results/Resource/{4AB2ADEA-B67D-48CA-9B87-7090BE901C57}
./History/Results/Resource/{36CBF669-6C28-4283-BEDE-6F4ECBB9335E}
./History/Results/Resource/{62ADA4E3-0651-4F7C-9BB5-B2FCC325071B}
./History/Results/Resource/{2E48A126-BAD6-4EEC-8D85-05E063E5B5DF}
./History/Results/Resource/{BC17C064-4D8A-4F8D-A809-AA39B05B56FE}
./History/Results/Resource/{BC51BBCF-1F05-4AFA-8731-069840B2308C}
./History/Results/Resource/{CCFF5139-D37E-4FBB-B799-4D3BFA755E1D}
./History/Results/Resource/{168C5E4D-269E-42E0-8CD1-E89FBA171823}
./History/Results/Resource/{B382797F-DE46-463B-A55E-7589D147D2D9}
./History/Results/Resource/{344B26F1-A0D7-47F7-AB42-AAC634F26A15}
./History/Results/Resource/{9BF84991-2C10-4074-9591-2AE14A5A12C3}
./History/Results/Resource/{AC7B5160-E901-417D-A235-32706877812A}
./History/Results/Quick
./History/Results/Quick/{C049D884-D304-4F86-86E1-80B4B258CC45}
./History/Results/Quick/{9EBFFACE-FF85-4BEF-B65F-9AD9EFEFE441}
./History/ReportLatency
./History/ReportLatency/Latency
./History/ReportLatency/Latency/22
./History/ReportLatency/Latency/01
./History/ReportLatency/Latency/12
./History/ReportLatency/Latency/19
./History/ReportLatency/Latency/20
./History/ReportLatency/Latency/04
./History/CacheManager
./History/CacheManager/205F5324-A62B-45C1-A13C-4845BD18E34E-0.bin
./History/Store
./MsMpEngSvc.dll
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.A0
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.6C
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.7E
./MpDiag.bin
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.79
./DefenderEcsCache.bin64
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.E6
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.67
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.83
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.DB
./MsMpEngCP.exe
./mpenginedb.db
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.7C
./CleanFileTelemetry
./FilesStash
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.01
./RtSigs
./RtSigs/Data
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.91
./BackupStore
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.80
./mpcache-3A136A7CCAA76D4ABC462E0EF513DFB3C597DF80.bin.9C
```

## Dump

Preferred forensic approach:

1. Take a VSS/shadow copy or offline disk image.
2. Locate `mpenginedb.db` and sidecars under Defender’s engine/platform directory.
3. Copy all files together from the snapshot.
4. Open the copy with SQLite tooling:

```powershell
sqlite3.exe mpenginedb.db ".tables"
sqlite3.exe mpenginedb.db ".schema"
sqlite3.exe mpenginedb.db ".backup dump.db"
```

If it opens:

```powershell
sqlite3.exe mpenginedb.db "SELECT name FROM sqlite_master WHERE type='table';"
sqlite3.exe mpenginedb.db "SELECT * FROM SQLiteGlobals;"
```

If it does not open, likely causes are:

- You copied without WAL/SHM sidecars.
- The file was copied while live and inconsistent.
- Access was blocked by Defender protection.
- SQLite codec/encryption is enabled.

**What to look for**

Expected logical tables/records correspond to MetaVault types:

- `BmProcessInfo`
- `BackupProcessInfo`
- `BmFileInfo`
- `FileHashes`
- `ProcessBlockHistory`
- `Anomaly`
- `AmsiFileCache`
- `Network`
- `NetworkIpFirewallRules`
- `AtomicCounters`
- `RollingQueues`
- `SQLiteGlobals`

Best mental model: `mpenginedb.db` is the persisted MetaVault. Live BM state additionally exists in memory inside `BmController`, `ProcessContext` maps, verdict caches, and ETW/BM queues.


# Cant decrypt mpengine.db

Stock `sqlite3` failing with `file is not a database` is consistent with Defender using a custom SQLite pager codec.

What I found in Ghidra:

- `MpSqliteCodecDisable` is checked in `FUN_1804f5f78`.
- If codec is not disabled, Defender calls:

```text
FUN_18098efe0(db, 0, 0)
  -> FUN_18098eff4
    -> FUN_18095a584
```

- `FUN_18095a584` installs codec hooks into the SQLite pager/Btree state.
- There is no obvious `sqlite3_key` or SQLCipher import. This appears compiled into Defender’s SQLite wrapper/amalgamation.
- `FUN_18098f5e8` validates that the decoded page 1 begins with `SQLite format 3`. That means the on-disk page is transformed, but after Defender’s codec it becomes normal SQLite pages.

So yes: it is probably encrypted or at least page-obfuscated. More likely “custom SQLite codec encryption” than simple XOR/header obfuscation.

Quick checks on your copied file:

```bash
xxd -l 64 mpenginedb.db
file mpenginedb.db
ls -l mpenginedb.db*
```

If first 16 bytes are not:

```text
SQLite format 3\0
```

then stock SQLite will reject it exactly as you saw.

If you copied only `mpenginedb.db`, also copy sidecars:

```text
mpenginedb.db
mpenginedb.db-wal
mpenginedb.db-shm
mpenginedb.db-journal
```

But missing WAL usually causes missing tables/corruption, not “file is not a database” if the main header is encoded.

Can you reverse it? In principle yes.

Practical paths:

1. Reverse the codec installed by `FUN_18095a584`, especially the callbacks at `FUN_180991fd0` and related page transform functions.
2. Reuse Defender’s own SQLite wrapper/codec in a controlled harness and call its open/query routines.
3. Dump decoded pages from a live Defender process after SQLite opens the DB.
4. If possible, find a system/config where `MpSqliteCodecDisable` was enabled before DB creation; that would likely create a normal SQLite DB, but it will not decrypt an already encoded one.

I would first confirm the first bytes. If they look random/high entropy, it is codec-protected. If they are all zero/truncated, it is a bad copy. If they start with `SQLite format 3`, then focus on WAL/copy consistency instead.


# Decrypt mpengine.db

The transform is RC4-like: key scheduling with the 256-byte constant at `0x180d2e220`, then PRGA XOR over page bytes. Since XOR stream ciphers are symmetric, you can decrypt offline by applying the same transform to the same byte ranges per page.

Your dump is exactly what I’d expect from Defender’s SQLite codec.

**What The Header Says**
`xxd`:

```text
00000000: 5bfc 4cf1 e798 fe0e ad8b fca6 f5da cf90
00000010: 1000 0202 0040 2020 ...
```

SQLite database header normally starts:

```text
SQLite format 3\0
```

But offsets `0x10..0x17` are meaningful SQLite header values:

```text
1000      page size = 4096
02        write version = WAL
02        read version = WAL
00        reserved bytes
40 20 20  payload fractions
```

So only parts of the page are encrypted/obfuscated. This is not a bad copy.

**What Defender Is Doing**
The codec callback is `FUN_180991fd0`.

For page 1 decode/encode, it does:

```c
if (pageNo == 1) {
    transform(buf + 0x00, 0x10);
    transform(buf + 0x18, pageSize - 0x18);
}
```

It intentionally leaves `0x10..0x17` plaintext. That matches your file.

The transform is `FUN_18092aa94`, which is RC4-like:

- Key schedule: `FUN_1808f9eac`
- PRGA/XOR: `FUN_1808f9e04`
- Static 256-byte key/table: `DAT_180d2e220`

Since RC4 XOR is symmetric, encrypt and decrypt are the same operation.

**Best Next Step: Practical Path 1**
Write an offline decoder that applies Defender’s transform to database pages.

Algorithm:

1. Extract the 256-byte key at Ghidra address `0x180d2e220`.
2. Implement the RC4-like KSA from `FUN_1808f9eac`.
3. Implement the PRGA from `FUN_1808f9e04`.
4. Process the DB by page.
5. For page 1:
   - decrypt bytes `0x00..0x0f`
   - skip bytes `0x10..0x17`
   - decrypt bytes `0x18..0xfff`
6. For pages `2..N`:
   - likely decrypt full page `0x00..0xfff`
7. Write output to `mpenginedb.dec.db`.
8. Test with `sqlite3 mpenginedb.dec.db ".schema"`.

Pseudo-Python shape:

```python
def rc4_crypt(data, key):
    s = list(range(256))
    j = 0
    key = bytes(key)

    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]

    i = 1
    j = 0
    out = bytearray(data)

    for n, b in enumerate(data):
        si = s[i]
        j = (j + si) & 0xff
        sj = s[j]
        s[i], s[j] = sj, si
        out[n] = b ^ s[(si + sj) & 0xff]
        i = (i + 1) & 0xff

    return bytes(out)
```

Your page size is `0x1000`.

The only missing piece is the 256-byte key from `DAT_180d2e220`.

**Why Path 2 Is Harder**
Reusing Defender’s own code is possible, but harder:

- The codec is not an exported `sqlite3_key`/SQLCipher API.
- It is compiled into Defender’s SQLite wrapper.
- You would need to load the right Defender DLL/EXE, initialize globals, and call internal functions with correct object layouts.
- It may depend on Defender runtime state, service config, and protected process context.

So I’d prioritize Path 1.

**Validation Targets**
After decoding, first bytes should become:

```bash
xxd -l 64 mpenginedb.dec.db
```

Expected:

```text
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
00000010: 1000 0202 0040 2020 ...
```

Then:

```bash
sqlite3 mpenginedb.dec.db "PRAGMA integrity_check;"
sqlite3 mpenginedb.dec.db ".tables"
sqlite3 mpenginedb.dec.db "SELECT * FROM SQLiteGlobals;"
```

If page 1 decodes but later pages fail, adjust page handling. Most likely page 1 has the special skipped header range, and all other pages use full-page transform.


# Script

Created `decrypt-mpenginedb.py`.

Use it like:

```bash
python3 decrypt-mpenginedb.py mpenginedb.db mpenginedb.dec.db --image /path/to/DefenderBinary.exe
```

Defaults:

- image base: `0x180000000`
- key VA: `0x180D2E220`
- page size auto-detected from offset `0x10`
- page 1 preserves bytes `0x10..0x17`

If the key is correct, output should start with:

```text
SQLite format 3
```

Then test:

```bash
sqlite3 mpenginedb.dec.db ".tables"
sqlite3 mpenginedb.dec.db "SELECT * FROM SQLiteGlobals;"
```

If it fails, try:

```bash
python3 decrypt-mpenginedb.py mpenginedb.db mpenginedb.dec.db --image mpengine.dll
```

Most important: use the exact Defender binary/build that created the DB, because the 256-byte key table may be build-specific.