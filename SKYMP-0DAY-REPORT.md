# VULN-REPORT: Unauthenticated remote memory-exhaustion DoS via unbounded deserialization loops (skymp5)

Status: 0-day (unpatched in skyrim-multiplayer/skymp main @ 2026-09-13)
Severity: CRITICAL (unauthenticated, single 6-byte UDP packet, affects every skymp5 server incl. Daedric Online)
CWE: CWE-1284 (unbounded quantity), CWE-252 (unchecked return value), CWE-456 (uninitialized variable), CWE-400 (resource exhaustion)

## Root cause chain

1. serialization/include/impl/BitStreamUtil.h:15-18
   `ReadFromBitStream` wrappers call `stream.Read(data)` and DISCARD the bool return.
   On stream underflow SLikeNet leaves `data` UNMODIFIED.

2. serialization/include/impl/BitStreamUtil.ipp:47-52
   `T value; ReadFromBitStream(stream, value); return value;` -> returns
   UNINITIALIZED stack garbage on underflow.

3. serialization/include/archives/BitStreamInputArchive.h:33-75
   StringLike and ContainerLike Serialize(): read `uint32_t n` from stream, then
   loop `n` times doing push_back of each element. No validation of `n` against
   remaining stream length. Attacker-controlled n up to 4,294,967,295.
   (TODO comment on lines 41/68 admits missing check.)

4. Reachability (unauthenticated):
   - skymp5-server/cpp/server_guest_lib/PartOne.cpp:915-923 HandleMessagePacket
     only checks IsConnected(userId) - no login, no actor, no profile required.
   - skymp5-server/cpp/mp_common/Networking.cpp:191-199 per-packet try/catch
     RETHROWS (`catch (std::exception& e) { throw; }`).
   - skymp5-server/cpp/server_guest_lib/PacketParser.cpp:42 calls Deserialize
     with no local try/catch.

## PoC packet (LAB ONLY)

MsgType::CustomPacket = 1 (MsgType.h:7), MinPacketId = 134 (MinPacketId.h:3).
CustomPacketMessage payload = std::string contentJsonDump (CustomPacketMessage.h:18).
Wire integers are BIG-ENDIAN (empirically verified against SLikeNet BitStream).

    Offset  Bytes              Meaning
    0       0x86 (134)         MinPacketId
    1       0x01 (1)           MsgType::CustomPacket
    2..5    FF FF FF FF        uint32 n = 4294967295 (endian-agnostic value)

Total: 6 bytes over the game protocol (UDP, RakNet/SLikeNet, port 7777).

## EMPIRICAL CONFIRMATION (local lab, Windows, g++ 16.2, 2026-09-13)

Harness: real skymp `serialization/include/archives/BitStreamInputArchive.h`
+ real SLikeNet `BitStream.cpp` + verbatim `CustomPacketMessage::Serialize`
shape; stream constructed exactly as MessageSerializerFactory.cpp:42-46.

    packet  86 01 00 10 00 00 (n=1M)        -> string 1,048,576 B,   3 ms
    packet  86 01 06 40 00 00 (n=100M)      -> string 104,857,600 B, 389 ms, peak RSS 124 MB
    packet  86 01 FF FF FF FF (n=4294967295)-> string 4,294,967,295 B, 17,431 ms, peak RSS 7,684 MB

Findings:
- Linear memory amplification ~1:700,000 (6 bytes -> 4.3 GiB).
- Main-thread block: 17.4 s per packet (game tick is single-threaded ->
  every connected player freezes / times out).
- Peak RSS 7.7 GiB (realloc doubling). On a typical 8-16 GiB game server:
  OOM-kill or total stall. A few packets in succession guarantee the kill.
- SLikeNet Read() on underflow returns false and leaves the target
  UNTOUCHED (dbg: value kept its pre-read content) -> loop pushes
  uninitialized stack garbage into the string (CWE-456); it is later handed
  to the gamemode JS layer as contentJsonDump (server memory disclosure
  surface into scripts/logs).

## Server behavior after receiving one packet

- BitStreamInputArchive::Serialize<string> reads n = 0xFFFFFFFF, then runs
  4.29e9 iterations of {Read char (fails silently, element = uninitialized
  stack byte), push_back}.
- Main tick thread blocks for tens of seconds -> all connected players freeze /
  time out (server single-threaded tick).
- std::string grows toward ~4 GiB; with realloc doubling, transient RSS up to
  ~8 GiB -> OOM-killer or std::bad_alloc.
- On bad_alloc the exception unwinds to ScampServer::Tick (ScampServer.cpp:478-489)
  which LOGS AND RETRIES the tick loop; a handful of repeated packets
  sustain memory pressure until the process is OOM-killed.
- Secondary: uninitialized stack/heap bytes are copied into contentJsonDump and
  handed to the gamemode JS layer (onCustomPacket) -> minor server-memory
  disclosure into script/log surfaces.

## Amplification variants

- SpellCastMessage (type 23): THREE attacker-sized vector<uint8_t> in one packet.
- CreateActorMessage (type 33): optional<vector<SetNodeTextureSetEntry>> where
  each entry contains a string -> nested unbounded loops; on underflow,
  uninitialized `hasValue` bools and sizes cause pseudo-random deep nesting
  (potential non-terminating loop).
- Any ContainerLike/StringLike field in any of the 30+ registered messages.

## Fix recommendation (upstream)

1. Check return value of every SLNet::BitStream::Read; throw on underflow.
2. Before element loops, validate n: `n * sizeof(element_wire_max) <= bs.GetNumberOfUnreadBits()/8`, else throw.
3. Initialize `element{}` in archive loops.
4. Wrap per-packet processing in Networking::Tick / PacketParser so one malformed
   packet cannot abort or rethrow out of the receive loop (currently rethrows,
   also enabling tick-loop retry storms).
5. Cap message/string sizes at protocol level (e.g. 1 MiB).
