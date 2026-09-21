# tencent-ace-anogs-notes

Notes on how Tencent's ACE anti-cheat (the `anogs` / AnoSDK component, "TSS"
internally) is put together on iOS, and why the obvious ways people try to
neutralize it get them banned or crash the app instead. This is analysis, not a
bypass cookbook, the whole point is that the naive patch is the wrong move and I
want to explain what the thing actually does before anyone pokes it.

If you maintain an app that ships ACE and you're debugging false positives or
crashes, or you're a researcher mapping mobile anti-cheat, this is for you.

## what anogs is, at a glance

`anogs` is a dylib the game loads. Inside you'll see:

- `AnoSDKInit` / `AnoSDKInitEx`, `AnoSDKSetUserInfo`, `AnoSDKOnRecvData`,
  `AnoSDKGetReportData[2/3/4]`, `AnoSDKIoctl` / `AnoSDKIoctlOld` as the exported
  surface
- a "TDM"/"REPORT" plugin that builds tamper reports
- integrity self-checks and an anti-debug layer
- a transport that ships reports off-device

It talks to a separate SDK (GCloudCore-style) that owns the actual HTTP, and it
integrates with the game's own networking too. Reports are the product: it
collects device/environment signals, decides if something's off, and sends a
verdict up. Bans are almost always server-side off those reports, not a local
decision.

## how to read it

Standard iOS RE applies, but a few anogs-specific things:

- **Strings are XOR-obfuscated.** The event names, path lists it probes for,
  detection labels, all encrypted. You'll need to break the table before the code
  makes sense. The good news is the log/format strings around the C++ scaffolding
  are often plaintext (`"init_info->size_:%d"`, `"...send_data_to_svr:%p"`), and
  those tell you struct layouts and where the important handoffs are.
- **It hides its libc/objc calls behind a resolver.** Instead of calling `send`
  or `open` through the normal stub, anogs resolves function pointers through an
  internal hashed lookup table and calls them indirectly. So a naive xref on
  `send` won't show anogs' own use, and inline-hooking a stub may not catch it.
  Figure out whether the resolver returns the real target or the GOT slot, that
  decides whether GOT-rebinding even reaches its calls.
- **Control flow is flattened in the sensitive functions.** The watchdog and init
  paths are CFG-obfuscated (state-machine dispatch with magic constants), and
  Hex-Rays output there is close to useless. Read those in raw asm and focus on
  the calls and the terminal behavior, not the pseudocode.

## the report pipeline (know it before you touch it)

Roughly: signal collectors → a report builder ("tdm_report" / "COREREPORT" event)
→ a queue → transport → HTTPS off device. The builder is gated by a config flag
(the server can turn report types on/off), and the wire body is serialized and
usually TLS-encrypted by the time it leaves.

Two consequences that trip everyone up:

1. By the time the report hits a raw socket `send`, it's already TLS ciphertext,
   so byte-matching the plaintext event name on the socket doesn't see it.
2. The report may go out over the SDK's own HTTPS client, over the game's
   transport, or via a callback the game registered, depending on how the host
   initialized it. Check which, `AnoSDKInitEx` may pass a null sender, meaning
   anogs sends it itself rather than through the game.

## the three traps that make "just patch it" fail

This is the part I actually want people to internalize.

**1. It checksums its own `__text`.** anogs verifies the integrity of its own code
pages. If you write a single byte into its `.text` (an inline hook, a `MOV X0,#0;
RET` on a report builder, anything), the checksum changes, and that mismatch is
itself a reportable event. So the classic "NOP the report function" gets you
flagged precisely because you modified the binary. Patching the build statically
has the same problem unless you also defeat the checksum, and defeating the
checksum is its own detected anomaly.

**2. There's a self-kill watchdog.** One of the init/integrity paths ends in
`kill(getpid(), 9)` when a check fails. So a patch that trips integrity doesn't
just get you banned later, it can hard-crash the process immediately. If your
"bypass" makes the app die on launch or a few seconds in, you probably tripped
this, not a bug in your hook.

**3. Hiding your presence can be more detectable than being present.** People try
to scrub the loaded-image list (`_dyld_get_image_name`, `task_info` with
`TASK_DYLD_INFO`, `proc_regionfilename`) to hide an injected dylib. Done
carelessly this creates anomalies that stand out more than the dylib would have,
a duplicated system library in the list, an anonymous executable region with no
backing file, an image count that disagrees with itself. Anti-cheat cross-checks
these. A clumsy hide is a signal.

## so what does "patching it right" even mean

Mostly it means *not patching anogs itself*, and understanding that a lot of what
looks like a fix is actually the thing that got you caught. For research/defensive
work the sane posture is:

- Don't write anogs' `.text`. Work at boundaries it doesn't checksum (your own
  caller's import table, OS-level behavior) rather than inside its code.
- Understand that silencing a report incorrectly (returning empty to a channel the
  SDK expects a real reply on) can itself be treated as tampering. The SDK has
  control channels that wait on responses, breaking those looks like an attack.
- Assume the ban is server-side. Local suppression of a popup or a kick doesn't
  change a verdict that already left the device.
- If you're chasing a specific outgoing report to understand it, capture it at the
  network layer on-device (proxy the traffic) rather than guessing at encrypted
  bodies statically. You'll learn far more from one real request than from a week
  of reversing the serializer.

## debugging false positives (the legitimate case)

If you ship a game with ACE and users hit false bans/crashes:

- reproduce with a symbolicated build and read the crash log, the watchdog kill
  and the anti-debug paths have recognizable signatures
- the `anort` / init return codes are documented enough internally to tell
  anti-debug from integrity from environment failures, map the code before you
  assume malice
- a lot of "sitting in game" crashes people blame on anti-cheat are actually the
  perf-telemetry sibling library, not anogs' detection, check which dylib the
  faulting frame is in before you go down the anti-cheat rabbit hole

## bottom line

anogs is a report engine with aggressive self-protection. The interesting
reversing is in the pipeline and the self-checks, not in finding a byte to flip,
because flipping the byte is what the self-checks exist to catch. Analyze it to
understand it. If your goal is to defeat it in a live game, understand that this
writeup deliberately stops at "here's how it works and why the easy attacks fail",
because that's the useful and defensible part.
