# ramdisc

A cross-platform in-memory disk with a small ext2-like filesystem that can build as a shared library (.so/.dll). It exposes a C API with both block-level access and file-level operations, optionally persisting to a backing file.

## Building

```
cmake -S . -B build -DRD_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Options (CMake cache):
- `RD_BUILD_SHARED` (ON): build shared library.
- `RD_BUILD_STATIC` (OFF): also build static lib.
- `RD_ENABLE_JOURNAL` (OFF): reserved; no-op.
- `RD_BUILD_TESTS` (ON): build test executable.

Outputs:
- Library target: `ramdisc` (alias `ramdisc::ramdisc`).
- Header: `include/ramdisc.h`.
- Tests: `build/ramdisc_tests`.

## Usage (C API)

Include the header and link against the library:

```c
#include "ramdisc.h"

int main() {
    rd_device_t dev = rd_create(1u << 20, 4096, NULL, 0);
    rd_mount(dev);

    rd_fd fd = rd_open(dev, "/hello", RD_O_CREATE | RD_O_RDWR | RD_O_TRUNC, 0644);
    const char msg[] = "hello";
    rd_write(dev, fd, msg, sizeof msg);
    rd_seek(dev, fd, 0, 0);
    char buf[16];
    rd_read(dev, fd, buf, sizeof msg);
    rd_close(dev, fd);

    rd_unlink(dev, "/hello");
    rd_unmount(dev);
    rd_destroy(dev);
    return 0;
}
```

### Initialization
- `rd_create(size_bytes, block_size, backing_path, flags)`: allocate a device. `block_size` must be a power of two. `backing_path` optional; when set, the device preloads from the file (unless truncated) and flushes to it. Flags:
  - `RD_BACKING_TRUNC`: truncate/create the backing file to `size_bytes`.
  - `RD_BACKING_CREATE`: (reserved) same as TRUNC currently.
  - `RD_BACKING_SPILL`: reserved, no-op.
  - `RD_JOURNAL_ENABLE`: reserved, no-op.
- `rd_mount(dev)`: format if the superblock is absent; otherwise validate and mount.
- `rd_unmount(dev)`: flush to backing and detach.
- `rd_destroy(dev)`: free memory, close backing.

### Block API
- `rd_block_read(dev, block_idx, buf, block_count)` / `rd_block_write(...)`: block-aligned I/O within bounds; returns blocks transferred or negative error.
- `rd_block_flush(dev)`: flush memory to backing file (if any).

### File API (minimal VFS)
- `rd_open(dev, path, flags, mode)`: `RD_O_CREATE`, `RD_O_TRUNC`, `RD_O_EXCL`, `RD_O_APPEND`, `RD_O_RDONLY/WRONLY/RDWR` supported.
- `rd_read`, `rd_write`, `rd_pread`, `rd_pwrite`, `rd_seek`, `rd_close`.
- `rd_stat`, `rd_fstat` (struct `rd_stat_info`), `rd_unlink`, `rd_mkdir`, `rd_rmdir`, `rd_readdir` (callback receives names and stats).

### Types and limits
- Names: `RD_MAX_NAME` (64 bytes). Paths are POSIX-style (`/` separated); no relative paths.
- Inode blocks: 8 direct + 1 single-indirect. Max file size ≈ `(8 + indirect_entries) * block_size`; with 4 KiB blocks, ~ (8 + 1024) blocks ≈ 4 MiB.
- Handles: up to 64 open file descriptors per device.
- Block size must divide device size.

## How it works
- Superblock + block bitmap + inode table + data blocks laid out in RAM (and mirrored to backing when present).
- Allocation: block bitmap tracks free blocks; inodes track direct blocks and an optional single-indirect block.
- Directories store variable-length entries similar to ext2; `rd_readdir` walks entries and supplies a callback.
- Reads of sparse holes return zeroed data.
- On `rd_unmount` or `rd_block_flush`, the entire in-memory image is written to the backing file if configured.

## Error model
Functions return `RD_OK` (0) or negative `rd_err` codes: `RD_ERR_NOENT`, `RD_ERR_EXIST`, `RD_ERR_NOSPC`, `RD_ERR_INVAL`, `RD_ERR_PERM`, `RD_ERR_RANGE`, `RD_ERR_NOMEM`, `RD_ERR_IO`, `RD_ERR_NOSYS`.

## Current limitations
- No permissions enforcement beyond simple mode checks; no users/groups.
- No journaling or crash recovery; backing flush is whole-image, not incremental.
- No double-indirect blocks; large files are limited to single-indirect capacity.
- No hard links or symlinks; no rename; no fsync per file (only full flush via `rd_block_flush`).
- Single-device, in-process only; not mounted into the OS VFS.
- Concurrency is not thread-safe yet (callers must serialize).

## Testing
- Build and run: `ctest --test-dir build --output-on-failure`.
- Coverage includes: mount/format, create/read/write/seek, directory listing, unlink/rmdir rules, indirect-block I/O, ENOSPC behavior, block API sanity, and backing persistence across remounts.
