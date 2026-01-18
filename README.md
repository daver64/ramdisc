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
- `RD_BUILD_FUSE` (OFF): build FUSE filesystem adapter.

Outputs:
- Library target: `ramdisc` (alias `ramdisc::ramdisc`).
- Header: `include/ramdisc.h`.
- Tests: `build/ramdisc_tests`.
- FUSE adapter: `build/ramdisc_fuse` (if `RD_BUILD_FUSE=ON`).

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
- File descriptors are integers starting from 0
- Initial capacity: 64 handles, grows dynamically up to 1024 as needed
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
- **Thread safety**: Thread-safe using pthread read-write locks and mutexes
  - Filesystem operations (reads, writes, metadata) protected by `pthread_rwlock_t`
  - Multiple concurrent readers allowed; writes are exclusive
  - File handle table protected by `pthread_mutex_t`
  - Expected overhead: 2-10% on concurrent workloads depending on contention

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
- **Block allocation**: O(1) using free list (was O(n))
- **Inode allocation**: O(1) using free list (was O(n))
- **Path lookup**: O(d × m) where d = path depth, m = entries per directory (linear search)
- **Directory add/remove**: O(m) where m = entries in directory
- **File read/write**: O(k) where k = blocks accessed; block lookup is O(1) direct, O(1) indirect
- **rd_readdir**: O(m) where m = entries in directory
- **rd_rename**: O(1) for file, O(depth) for directory cycle detection

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
- No hard links or symlinks.
- Single-device, in-process only; not mounted into the OS VFS.
- Handle table grows dynamically but caps at 1024 open files per device.

## Recent improvements (v0.4)
- **O(1) allocation**: Free list-based block and inode allocation for constant-time performance
  - Previous O(n) linear search replaced with linked free lists
  - Dramatically faster allocation on large devices
- **Rename operation**: Full rd_rename() implementation with cycle detection
  - Supports file and directory renames
  - Handles overwrites with proper checks
  - Detects and prevents directory cycles
- **Per-file fsync**: rd_fsync() flushes specific file's blocks to backing storage
  - More efficient than full rd_block_flush() for single file updates
  - Flushes file data, metadata, and directory entries
- **Thread safety**: Full thread-safe implementation using pthread read-write locks
  - Multiple concurrent readers for maximum performance
  - Exclusive write locking for modifications
  - Separate handle table mutex for minimal contention
- **Double indirect blocks**: Files can now grow up to ~4GB (with 4KB blocks) instead of ~4MB
- **Incremental backing flush**: Only dirty blocks written to backing file, dramatically faster for large devices
- **Dynamic file handles**: Handle table grows from 64 to 1024 as needed
- **Dirty tracking**: Backing file writes are now O(d) where d = dirty blocks

## Testing
- Build and run: `ctest --test-dir build --output-on-failure`.
- Coverage includes: mount/format, create/read/write/seek, directory listing, unlink/rmdir rules, indirect-block I/O, ENOSPC behavior, block API sanity, backing persistence across remounts, rename operations, per-file fsync, thread safety.
- 18 tests total, all passing.

## FUSE Filesystem Adapter

The FUSE adapter allows you to mount your ramdisc as a real directory in your filesystem, making it accessible to any application using standard POSIX file operations.

### Building with FUSE

First, install FUSE development libraries:
```bash
# Debian/Ubuntu
sudo apt-get install libfuse-dev

# Fedora/RHEL
sudo dnf install fuse-devel

# macOS (using FUSE for macOS)
brew install macfuse
```

Build with FUSE support:
```bash
cmake -S . -B build -DRD_BUILD_FUSE=ON
cmake --build build
```

### Using the FUSE Adapter

#### Quick Start

Mount a 64 MB ramdisc (runs in background):
```bash
mkdir /tmp/myram
./build/ramdisc_fuse /tmp/myram
```

Use it like any directory:
```bash
echo "Hello from FUSE!" > /tmp/myram/test.txt
cat /tmp/myram/test.txt
mkdir /tmp/myram/subdir
cp /etc/hosts /tmp/myram/
ls -la /tmp/myram/
```

Unmount when done:
```bash
fusermount -u /tmp/myram
```

#### Advanced Usage

Mount with custom size (256 MB):
```bash
./build/ramdisc_fuse -o size=256 /tmp/myram
```

Mount with backing file for persistence:
```bash
# First mount - creates and uses backing file
./build/ramdisc_fuse -o backing=/tmp/ramdisc.img /tmp/myram
echo "persistent data" > /tmp/myram/file.txt
fusermount -u /tmp/myram

# Later mount - data persists!
./build/ramdisc_fuse -o backing=/tmp/ramdisc.img /tmp/myram
cat /tmp/myram/file.txt  # Shows "persistent data"
```

Run in foreground (useful for debugging):
```bash
./build/ramdisc_fuse -f /tmp/myram
# Press Ctrl+C to unmount
```

Enable debug output:
```bash
./build/ramdisc_fuse -d -f /tmp/myram
```

#### Real-World Examples

**Use as fast tmpfs replacement:**
```bash
./build/ramdisc_fuse -o size=512 /tmp/fast
cd /tmp/fast
# Compile projects, extract archives, etc.
```

**Run SQLite database in RAM:**
```bash
./build/ramdisc_fuse -o size=128 /tmp/db
sqlite3 /tmp/db/test.db "CREATE TABLE users (id INT, name TEXT);"
sqlite3 /tmp/db/test.db "INSERT INTO users VALUES (1, 'Alice');"
```

**Development workspace with persistence:**
```bash
./build/ramdisc_fuse -o size=1024,backing=$HOME/.ramdisc.img /tmp/workspace
# Your files persist across reboots via backing file
```

**Check filesystem status:**
```bash
df -h /tmp/myram          # Show capacity and usage
mount | grep ramdisc_fuse # Verify mount
tree /tmp/myram           # View directory structure
```

### FUSE Options

- `-o size=MB` - Set ramdisc size in megabytes (default: 64)
- `-o backing=PATH` - Use a backing file for persistence
- `-f` - Run in foreground (blocks terminal, Ctrl+C to unmount)
- `-d` - Enable FUSE debug output (implies `-f`)
- `-s` - Single-threaded mode (useful for debugging)
- `-o allow_other` - Allow other users to access (requires user_allow_other in /etc/fuse.conf)

### Supported Operations

All standard POSIX file operations work:
- **Files**: create, read, write, truncate, delete
- **Directories**: create, list, delete (when empty)
- **Operations**: rename, stat, fsync
- **Access modes**: read-only, write-only, read-write
- **Seek modes**: SEEK_SET, SEEK_CUR, SEEK_END

Example workflow:
```bash
# Create and edit files with any tool
vim /tmp/myram/notes.txt
echo "data" > /tmp/myram/file.txt

# Standard utilities work
cp -r /etc/ssl/certs /tmp/myram/
tar xzf archive.tar.gz -C /tmp/myram/
find /tmp/myram -name "*.txt"

# Applications see it as a normal filesystem
sqlite3 /tmp/myram/database.db
gcc -o /tmp/myram/program source.c
```

### Troubleshooting

**Mount fails with "mountpoint is not empty":**
```bash
# Clean the directory first
rm -rf /tmp/myram/*
# Or use the nonempty option (not recommended)
./build/ramdisc_fuse -o nonempty /tmp/myram
```

**Check if mounted:**
```bash
mount | grep ramdisc_fuse
df -h /tmp/myram
```

**Unmount stuck filesystem:**
```bash
# Lazy unmount
fusermount -uz /tmp/myram

# Force unmount (if lazy doesn't work)
sudo umount -l /tmp/myram
```

**Permission denied errors:**
```bash
# Ensure you have permission to the mount point
ls -ld /tmp/myram

# For multi-user access, add allow_other option
./build/ramdisc_fuse -o allow_other /tmp/myram
```

### Benefits of FUSE Integration

- **Zero code changes**: Existing applications work without modification
- **Standard tools**: Use `ls`, `cp`, `mv`, `cat`, etc.
- **Editor support**: Any text editor can open files directly
- **Database support**: Run SQLite or other databases on ramdisc
- **Mount anywhere**: Integrate seamlessly into your filesystem hierarchy
- **Fast tmpfs alternative**: With ext2-like structure and optional persistence

### Limitations

- Same as C API: max file size ~4GB (with 4KB blocks and double indirect)
- 64-character filename limit
- No symbolic links or hard links yet
- No extended attributes
- FUSE adds some overhead vs. direct C API usage

