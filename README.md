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
Functions return `RD_OK` (0) or negative `rd_err` codes:
- `RD_ERR_IO` (-1): I/O error (backing file, corrupted internal structures)
- `RD_ERR_NOENT` (-2): File/directory not found
- `RD_ERR_EXIST` (-3): File/directory already exists (with O_EXCL)
- `RD_ERR_NOSPC` (-4): No space left (blocks or inodes exhausted)
- `RD_ERR_INVAL` (-5): Invalid argument (null pointer, bad path, invalid whence)
- `RD_ERR_PERM` (-6): Operation not permitted (unlink directory, write to directory, rmdir non-empty)
- `RD_ERR_RANGE` (-7): Out of range (block index, file size beyond indirect limit)
- `RD_ERR_NOMEM` (-8): Memory allocation failed
- `RD_ERR_NOSYS` (-9): Not implemented (reserved for future features)

### Function-specific error codes
- **rd_create**: Returns NULL and sets `errno` on failure (EINVAL, ENOMEM)
- **rd_open**: Returns RD_ERR_NOENT (not found), RD_ERR_EXIST (O_EXCL), RD_ERR_NOSPC (no handles/inodes), RD_ERR_PERM (write to directory)
- **rd_read/write**: Returns RD_ERR_INVAL (bad fd/type), RD_ERR_NOSPC (allocation failure), bytes transferred on success
- **rd_seek**: Returns RD_ERR_INVAL (bad fd/whence, negative result); whence: 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END
- **rd_stat**: Returns RD_ERR_NOENT (not found), RD_ERR_INVAL (bad args)
- **rd_mkdir**: Returns RD_ERR_EXIST (already exists), RD_ERR_NOSPC (no inodes/blocks)
- **rd_rmdir**: Returns RD_ERR_PERM (non-empty or not directory), RD_ERR_NOENT (not found)
- **rd_unlink**: Returns RD_ERR_PERM (is directory or root), RD_ERR_NOENT (not found)

## API contracts and behavior

### File descriptors
- File descriptors are integers in range [0, 64)
- Each `rd_open` allocates a new handle; same file can be opened multiple times
- Each handle maintains independent position offset
- Closing an fd makes it available for reuse
- Using a closed fd returns RD_ERR_INVAL
- Destroying device invalidates all fds (no automatic cleanup)

### File operations
- **Reads** beyond EOF return 0 (not an error); partial reads to EOF return actual bytes
- **Writes** extend file automatically; may fail with RD_ERR_NOSPC or RD_ERR_RANGE (beyond indirect limit)
- **Sparse files**: Unallocated blocks read as zeros; blocks allocated on write
- **O_APPEND**: Seeks to end before each write (position set at open and per write)
- **O_TRUNC**: Immediately frees all blocks and resets size to 0; updates mtime/ctime
- **pread/pwrite**: Do not modify file position
- **Concurrent access**: Multiple handles to same file see each other's writes immediately (no buffering)

### Directory operations
- Directories initially contain \".\" (self) and \"..\" (parent) with link count 2
- Root directory's \"..\" points to itself
- `rd_readdir` calls callback for each entry including \".\" and \"..\"; callback can return non-zero to stop iteration
- Empty directory check ignores \".\" and \"..\"; `rd_rmdir` fails on non-empty with RD_ERR_PERM
- Directory link count = 2 + number of subdirectories

### Memory and lifecycle
- `rd_create` allocates aligned memory for entire device; fails if allocation fails
- `rd_mount` formats if no valid superblock; validates existing superblock
- `rd_unmount` flushes to backing file (if present); does not free memory
- `rd_destroy` frees all memory and closes backing file; does not flush (call rd_unmount first)
- **Thread safety**: Not thread-safe; caller must serialize access

### Limits
- Max open file descriptors: 64 initially, grows dynamically up to 1024 per device
- Max filename length: 63 bytes + null terminator (RD_MAX_NAME = 64)
- Max path length: 255 bytes (temp buffer in rd_lookup)
- Max file size with 4KB blocks: ~4GB (8 direct + 1024 single-indirect + 1024×1024 double-indirect blocks)
  - Direct: 8 × 4KB = 32KB
  - Single indirect: 1024 × 4KB = 4MB
  - Double indirect: 1024 × 1024 × 4KB = 4GB
- Max directory entries per block: varies by name length
- Block size: Must be power of 2
- Device size: Must be multiple of block_size

## Performance characteristics

### Time complexity
- **Block allocation**: O(n) where n = block_count; linear search from data_start
- **Inode allocation**: O(n) where n = inode_count; linear search
- **Path lookup**: O(d × m) where d = path depth, m = entries per directory (linear search)
- **Directory add/remove**: O(m) where m = entries in directory
- **File read/write**: O(k) where k = blocks accessed; block lookup is O(1) direct, O(1) indirect
- **rd_readdir**: O(m) where m = entries in directory

### Space overhead
- **Superblock**: 1 block (stores metadata)
- **Block bitmap**: ⌈block_count / 8 / block_size⌉ blocks
- **Inode table**: ⌈inode_count × 64 / block_size⌉ blocks (64 bytes per inode)
- **Directory entries**: ~16-80 bytes per entry (depends on name length, 4-byte aligned)
- **Example**: 1MB device, 4KB blocks → 256 blocks, 64 inodes, ~5% overhead (superblock + 1 bitmap + 1 inode block)

### Memory usage
- Entire device held in RAM (size_bytes allocated with rd_create)
- No page cache or buffer cache (direct memory access)
- Backing file (if used) uses incremental writes via dirty block tracking
  - Only modified blocks flushed on rd_block_flush/rd_unmount
  - Dirty bitmap overhead: ⌈block_count / 8⌉ bytes
  - Example: 1GB device with 4KB blocks = 256K blocks = 32KB dirty bitmap

## Current limitations
- No permissions enforcement beyond simple mode checks; no users/groups.
- No journaling or crash recovery; backing flush is incremental (dirty blocks only) but not atomic.
- No hard links or symlinks; no rename; no fsync per file (only full flush via `rd_block_flush`).
- Single-device, in-process only; not mounted into the OS VFS.
- Concurrency is not thread-safe yet (callers must serialize).
- Handle table grows dynamically but caps at 1024 open files per device.

## Recent improvements (v0.2)
- **Double indirect blocks**: Files can now grow up to ~4GB (with 4KB blocks) instead of ~4MB
- **Incremental backing flush**: Only dirty blocks written to backing file, dramatically faster for large devices
- **Dynamic file handles**: Handle table grows from 64 to 1024 as needed, no hard limit on concurrent opens
- **Dirty tracking**: Backing file writes are now O(d) where d = dirty blocks, not O(n) where n = total blocks

## Testing
- Build and run: `ctest --test-dir build --output-on-failure`.
- Coverage includes: mount/format, create/read/write/seek, directory listing, unlink/rmdir rules, indirect-block I/O, ENOSPC behavior, block API sanity, and backing persistence across remounts.
