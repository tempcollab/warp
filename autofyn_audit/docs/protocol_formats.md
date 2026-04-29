# Warp Protocol Wire Formats

**Audit Firm:** AutoFyn Security  
**Commit:** `404bfbeb8f4a2e07ca9063b45993590609416c98`  
**Classification:** CONFIDENTIAL

---

## IPC Protocol (Local — crates/ipc/)

### Overview

The IPC protocol is used for local inter-process communication between Warp
processes on the same machine. It operates over Unix domain sockets.

### Socket Path

```
/tmp/warp-ipc-{random}.sock
```

The `{random}` component is generated at process startup and is not guessable.
However, the socket path pattern is discoverable via `ls /tmp/warp-ipc-*.sock`.

### Wire Format

```
+------------------+---------------------------+
|   Length Prefix  |         Payload           |
|   (8 bytes)      |   (length bytes)          |
+------------------+---------------------------+
  big-endian usize    bincode-serialized message
```

**Field details:**

| Field | Size | Encoding | Notes |
|-------|------|----------|-------|
| Length | 8 bytes | Big-endian unsigned integer (`usize`) | Number of payload bytes that follow |
| Payload | `length` bytes | bincode serialization | Rust struct deserialized with `bincode::deserialize` |

### Critical: No Size Limit (VULN-003)

**Source:** `crates/ipc/src/protocol.rs:181-185`

```rust
let payload_len = usize::from_be_bytes(header_buf);
let mut payload_buf = vec![0; payload_len];  // NO BOUNDS CHECK
reader.read_exact(&mut payload_buf).await?;
```

There is **no maximum message size** enforced before allocating `payload_len` bytes.
Sending `0xFFFFFFFFFFFFFFFF` as the length header causes Warp to attempt allocating
~18 exabytes, resulting in OOM kill.

**Contrast with remote daemon** (below): the remote protocol enforces a 64 MB hard limit.

---

## Remote Daemon Protocol (Remote — crates/remote_server/)

### Overview

The remote server daemon runs on remote hosts and handles file operations,
command execution, and AI context requests on behalf of the local Warp client.
It listens on a Unix domain socket and communicates over protobuf.

### Socket Path

```
~/.warp/remote-server/{identity_key}/server.sock
```

The `{identity_key}` is derived from an SSH identity key fingerprint. The socket
is created with mode `0600` (owner read/write only).

**Source:** `crates/remote_server/src/unix/mod.rs`, `proxy.rs:39`

### Wire Format

```
+------------------+---------------------------+
|   Length Prefix  |         Payload           |
|   (4 bytes)      |   (length bytes)          |
+------------------+---------------------------+
  little-endian u32   protobuf-encoded message
```

**Field details:**

| Field | Size | Encoding | Notes |
|-------|------|----------|-------|
| Length | 4 bytes | Little-endian unsigned 32-bit integer | Number of payload bytes that follow |
| Payload | `length` bytes | Protocol Buffers (protobuf) | Decoded with the `prost` crate |

### Size Limit

The remote daemon enforces a **64 MB maximum message size**.

**Source:** `crates/remote_server/src/protocol.rs` (MAX_MESSAGE_SIZE constant)

Any message with a length prefix exceeding 64 MB is rejected before allocation.

---

## Protocol Comparison

| Attribute | IPC (local) | Remote Daemon |
|-----------|-------------|---------------|
| Socket path | `/tmp/warp-ipc-{random}.sock` | `~/.warp/remote-server/{key}/server.sock` |
| Length prefix size | 8 bytes | 4 bytes |
| Byte order | Big-endian | Little-endian |
| Serialization format | bincode | protobuf (prost) |
| Maximum message size | **NONE** (VULN-003) | 64 MB |
| Authentication | None (Unix socket access control) | `auth_token` field (stored but **not checked** — VULN-005) |

---

## Security Notes

### VULN-003: IPC Unbounded Allocation

The local IPC protocol has no `MAX_MESSAGE_SIZE`. Any local process that can
enumerate and connect to the IPC socket can crash Warp with an OOM by sending
an 8-byte header containing `0xFF * 8`.

**Fix:** Add a `MAX_MESSAGE_SIZE` constant (e.g., 64 MB matching the remote daemon)
and reject messages that exceed it before allocation.

### VULN-005: Remote Daemon Auth Token Not Verified

The remote daemon stores the `auth_token` from the `Initialize` message but
**never checks it** before dispatching WriteFile, DeleteFile, or ReadFileContext
messages. Any client that can reach the socket (e.g., via SSH) can issue
arbitrary file operations.

**Fix:** Add auth_token verification in `handle_message` before routing to
WriteFile/DeleteFile/ReadFileContext handlers.
