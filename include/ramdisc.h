#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(_WIN32)
#  if defined(RD_STATIC)
#    define RD_API
#  elif defined(RD_BUILD_DLL)
#    define RD_API __declspec(dllexport)
#  else
#    define RD_API __declspec(dllimport)
#  endif
#else
#  define RD_API __attribute__((visibility("default")))
#endif

typedef struct rd_device* rd_device_t;
typedef int rd_fd;

typedef enum {
    RD_OK = 0,
    RD_ERR_IO = -1,
    RD_ERR_NOENT = -2,
    RD_ERR_EXIST = -3,
    RD_ERR_NOSPC = -4,
    RD_ERR_INVAL = -5,
    RD_ERR_PERM = -6,
    RD_ERR_RANGE = -7,
    RD_ERR_NOMEM = -8,
    RD_ERR_NOSYS = -9
} rd_err;

#define RD_MAX_NAME 64

typedef enum {
    RD_FT_UNKNOWN = 0,
    RD_FT_FILE = 1,
    RD_FT_DIR = 2
} rd_file_type;

typedef enum {
    RD_BACKING_CREATE = 1u << 0,
    RD_BACKING_TRUNC = 1u << 1,
    RD_BACKING_SPILL = 1u << 2,
    RD_JOURNAL_ENABLE = 1u << 3
} rd_create_flags;

typedef enum {
    RD_O_RDONLY = 0,
    RD_O_WRONLY = 1u << 0,
    RD_O_RDWR = 1u << 1,
    RD_O_CREATE = 1u << 2,
    RD_O_TRUNC = 1u << 3,
    RD_O_EXCL = 1u << 4,
    RD_O_APPEND = 1u << 5
} rd_open_flags;

typedef struct rd_stat_info {
    uint64_t size_bytes;
    uint32_t mode;
    uint32_t type; /* rd_file_type */
    uint64_t atime_ns;
    uint64_t mtime_ns;
    uint64_t ctime_ns;
    uint32_t link_count;
} rd_stat_info;

typedef int (*rd_dirent_cb)(const char* name, const rd_stat_info* st, void* user);

RD_API rd_device_t rd_create(size_t size_bytes,
                             size_t block_size,
                             const char* backing_path,
                             unsigned flags);

RD_API int rd_mount(rd_device_t dev);
RD_API int rd_unmount(rd_device_t dev);
RD_API void rd_destroy(rd_device_t dev);

RD_API ssize_t rd_block_read(rd_device_t dev,
                             size_t block_idx,
                             void* buf,
                             size_t block_count);

RD_API ssize_t rd_block_write(rd_device_t dev,
                              size_t block_idx,
                              const void* buf,
                              size_t block_count);

RD_API int rd_block_flush(rd_device_t dev);

RD_API rd_fd rd_open(rd_device_t dev, const char* path, unsigned flags, unsigned mode);
RD_API ssize_t rd_read(rd_device_t dev, rd_fd fd, void* buf, size_t len);
RD_API ssize_t rd_write(rd_device_t dev, rd_fd fd, const void* buf, size_t len);
RD_API ssize_t rd_pread(rd_device_t dev, rd_fd fd, void* buf, size_t len, size_t off);
RD_API ssize_t rd_pwrite(rd_device_t dev, rd_fd fd, const void* buf, size_t len, size_t off);
RD_API int rd_seek(rd_device_t dev, rd_fd fd, long long off, int whence);
RD_API int rd_close(rd_device_t dev, rd_fd fd);
RD_API int rd_fstat(rd_device_t dev, rd_fd fd, rd_stat_info* st);
RD_API int rd_stat(rd_device_t dev, const char* path, rd_stat_info* st);
RD_API int rd_unlink(rd_device_t dev, const char* path);
RD_API int rd_rename(rd_device_t dev, const char* old_path, const char* new_path);
RD_API int rd_mkdir(rd_device_t dev, const char* path);
RD_API int rd_rmdir(rd_device_t dev, const char* path);
RD_API int rd_readdir(rd_device_t dev, const char* path, rd_dirent_cb cb, void* user);
RD_API int rd_fsync(rd_device_t dev, rd_fd fd);

#ifdef __cplusplus
}
#endif
