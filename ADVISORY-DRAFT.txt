GITHUB PRIVATE SECURITY ADVISORY DRAFT (skyrim-multiplayer/skymp)

Title:
Unauthenticated remote memory-exhaustion DoS and uninitialized-memory
disclosure via unbounded deserialization loops in BitStreamInputArchive

Affected:
skymp5-server (all versions using serialization/include/archives/
BitStreamInputArchive.h; verified on main @ 2026-09-13, commit of
2026-09-10). All deployed skymp5 game servers are affected, including
public production servers with hundreds of concurrent players.

Summary:
The binary message deserializer reads an attacker-controlled uint32
element count for every string/container field and then iterates that
many times without validating the count against the remaining stream
size. SLikeNet BitStream::Read() failures are silently ignored and leave
element variables uninitialized. A single 6-byte UDP packet sent by any
connected client BEFORE authentication (login/JWT not required, see
PartOne::HandleMessagePacket IsConnected-only check) makes the server
build a 4 GiB string, blocking the single-threaded game tick for ~17 s
and peaking at ~7.7 GiB RSS (measured). Repeated packets reliably
OOM-kill the server. Uninitialized stack/heap bytes are copied into
message fields (e.g. CustomPacketMessage::contentJsonDump) and handed
to the gamemode JS layer.

CVSS 3.1 (proposed): 8.6 High
AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:H
(PR:N — only a bare UDP connection is needed, no account/actor)

PoC (do not run against production):
Packet bytes: 86 01 FF FF FF FF  (MinPacketId=134, MsgType::CustomPacket=1,
uint32 count = 0xFFFFFFFF, wire order big-endian)

Lab measurements (Windows, g++ 16.2, harness using the real
BitStreamInputArchive + SLikeNet BitStream):
  n=1M        -> 1,048,576-byte string,   3 ms
  n=100M      -> 104,857,600-byte string, 389 ms, 124 MB peak RSS
  n=4294967295-> 4,294,967,295-byte string, 17,431 ms, 7,684 MB peak RSS

Root cause files:
1. serialization/include/impl/BitStreamUtil.h:15-18  — Read() return value discarded
2. serialization/include/impl/BitStreamUtil.ipp:47-52 — uninitialized T returned on underflow
3. serialization/include/archives/BitStreamInputArchive.h:33-75 — unvalidated count loop (TODO admits missing check)
4. skymp5-server/cpp/server_guest_lib/PartOne.cpp:915-923 — parse before auth
5. skymp5-server/cpp/mp_common/Networking.cpp:191-199 — catch-and-rethrow aborts receive loop

Suggested fix: see attached patch (bounds-check counts against
GetNumberOfUnreadBits(), zero-init elements, propagate Read() failure,
make per-packet handling non-fatal).

Amplification variants: SpellCastMessage (3 attacker-sized vectors in
one packet), CreateActorMessage (nested optional<vector<struct{string}>>
with uninitialized control bytes -> pseudo-random deep nesting).

Timeline:
2026-09-13 discovered during authorized owner-side security assessment
(Daedric Online, owner-authorized); reported to upstream first.
Request: 90-day disclosure window; patch upstream, then notify server
operators.
