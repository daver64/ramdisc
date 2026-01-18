#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "ramdisc.h"

static rd_device_t g_device = NULL;

/* Convert ramdisc error codes to errno values */
static int rd_to_errno(int rd_err) {
    switch (rd_err) {
        case RD_OK: return 0;
        case RD_ERR_NOENT: return -ENOENT;
        case RD_ERR_EXIST: return -EEXIST;
        case RD_ERR_NOSPC: return -ENOSPC;
        case RD_ERR_INVAL: return -EINVAL;
        case RD_ERR_PERM: return -EPERM;
        case RD_ERR_RANGE: return -ERANGE;
        case RD_ERR_NOMEM: return -ENOMEM;
        case RD_ERR_NOSYS: return -ENOSYS;
        case RD_ERR_IO: return -EIO;
        default: return -EIO;
    }
}

/* Convert open() flags to ramdisc flags */
static unsigned int flags_to_rd(int flags) {
    unsigned int rd_flags = 0;
    
    if ((flags & O_ACCMODE) == O_RDONLY) {
        rd_flags |= RD_O_RDONLY;
    } else if ((flags & O_ACCMODE) == O_WRONLY) {
        rd_flags |= RD_O_WRONLY;
    } else if ((flags & O_ACCMODE) == O_RDWR) {
        rd_flags |= RD_O_RDWR;
    }
    
    if (flags & O_CREAT) rd_flags |= RD_O_CREATE;
    if (flags & O_TRUNC) rd_flags |= RD_O_TRUNC;
    if (flags & O_EXCL) rd_flags |= RD_O_EXCL;
    if (flags & O_APPEND) rd_flags |= RD_O_APPEND;
    
    return rd_flags;
}

/* Convert ramdisc stat to POSIX stat */
static void rd_stat_to_stat(const rd_stat_info *rd_st, struct stat *st) {
    memset(st, 0, sizeof(*st));
    
    st->st_size = rd_st->size_bytes;
    st->st_mode = rd_st->mode;
    st->st_nlink = rd_st->link_count;
    
    /* Convert file type */
    if (rd_st->type == RD_FT_DIR) {
        st->st_mode |= S_IFDIR;
    } else if (rd_st->type == RD_FT_FILE) {
        st->st_mode |= S_IFREG;
    }
    
    /* Convert nanosecond timestamps to timespec */
    st->st_atim.tv_sec = rd_st->atime_ns / 1000000000ULL;
    st->st_atim.tv_nsec = rd_st->atime_ns % 1000000000ULL;
    st->st_mtim.tv_sec = rd_st->mtime_ns / 1000000000ULL;
    st->st_mtim.tv_nsec = rd_st->mtime_ns % 1000000000ULL;
    st->st_ctim.tv_sec = rd_st->ctime_ns / 1000000000ULL;
    st->st_ctim.tv_nsec = rd_st->ctime_ns % 1000000000ULL;
    
    /* Default values */
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
    st->st_blocks = (rd_st->size_bytes + 511) / 512;
}

static int ramdisc_getattr(const char *path, struct stat *stbuf) {
    rd_stat_info info;
    int ret = rd_stat(g_device, path, &info);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    rd_stat_to_stat(&info, stbuf);
    return 0;
}

struct readdir_context {
    void *buf;
    fuse_fill_dir_t filler;
};

static int readdir_callback(const char *name, const rd_stat_info *st, void *user) {
    struct readdir_context *ctx = (struct readdir_context *)user;
    struct stat stbuf;
    
    rd_stat_to_stat(st, &stbuf);
    ctx->filler(ctx->buf, name, &stbuf, 0);
    
    return 0;
}

static int ramdisc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi) {
    (void)offset;
    (void)fi;
    
    struct readdir_context ctx = { .buf = buf, .filler = filler };
    
    /* Add standard entries */
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    
    int ret = rd_readdir(g_device, path, readdir_callback, &ctx);
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static int ramdisc_open(const char *path, struct fuse_file_info *fi) {
    unsigned int rd_flags = flags_to_rd(fi->flags);
    
    rd_fd fd = rd_open(g_device, path, rd_flags, 0644);
    if (fd < 0) {
        return rd_to_errno(fd);
    }
    
    fi->fh = (uint64_t)fd;
    return 0;
}

static int ramdisc_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode;
    
    unsigned int rd_flags = flags_to_rd(fi->flags) | RD_O_CREATE | RD_O_TRUNC;
    
    rd_fd fd = rd_open(g_device, path, rd_flags, 0644);
    if (fd < 0) {
        return rd_to_errno(fd);
    }
    
    fi->fh = (uint64_t)fd;
    return 0;
}

static int ramdisc_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    (void)path;
    
    rd_fd fd = (rd_fd)fi->fh;
    ssize_t bytes = rd_pread(g_device, fd, buf, size, offset);
    
    if (bytes < 0) {
        return rd_to_errno((int)bytes);
    }
    
    return bytes;
}

static int ramdisc_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi) {
    (void)path;
    
    rd_fd fd = (rd_fd)fi->fh;
    ssize_t bytes = rd_pwrite(g_device, fd, buf, size, offset);
    
    if (bytes < 0) {
        return rd_to_errno((int)bytes);
    }
    
    return bytes;
}

static int ramdisc_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    
    rd_fd fd = (rd_fd)fi->fh;
    int ret = rd_close(g_device, fd);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static int ramdisc_unlink(const char *path) {
    int ret = rd_unlink(g_device, path);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static int ramdisc_mkdir(const char *path, mode_t mode) {
    (void)mode;
    
    int ret = rd_mkdir(g_device, path);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static int ramdisc_rmdir(const char *path) {
    int ret = rd_rmdir(g_device, path);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static int ramdisc_rename(const char *from, const char *to) {
    int ret = rd_rename(g_device, from, to);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static int ramdisc_truncate(const char *path, off_t size) {
    /* Open, truncate via seeking and writing, then close */
    rd_fd fd = rd_open(g_device, path, RD_O_RDWR | RD_O_TRUNC, 0644);
    if (fd < 0) {
        return rd_to_errno(fd);
    }
    
    /* If truncating to non-zero size, seek and write a byte */
    if (size > 0) {
        int ret = rd_seek(g_device, fd, size - 1, 0);
        if (ret < 0) {
            rd_close(g_device, fd);
            return rd_to_errno(ret);
        }
        
        char zero = 0;
        ssize_t written = rd_write(g_device, fd, &zero, 1);
        if (written < 0) {
            rd_close(g_device, fd);
            return rd_to_errno((int)written);
        }
    }
    
    rd_close(g_device, fd);
    return 0;
}

static int ramdisc_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)path;
    
    rd_fd fd = (rd_fd)fi->fh;
    
    /* Seek to desired size - 1 and write a byte */
    if (size > 0) {
        int ret = rd_seek(g_device, fd, size - 1, 0);
        if (ret < 0) {
            return rd_to_errno(ret);
        }
        
        char zero = 0;
        ssize_t written = rd_write(g_device, fd, &zero, 1);
        if (written < 0) {
            return rd_to_errno((int)written);
        }
    }
    
    return 0;
}

static int ramdisc_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    (void)path;
    (void)isdatasync;
    
    rd_fd fd = (rd_fd)fi->fh;
    int ret = rd_fsync(g_device, fd);
    
    if (ret < 0) {
        return rd_to_errno(ret);
    }
    
    return 0;
}

static struct fuse_operations ramdisc_oper = {
    .getattr    = ramdisc_getattr,
    .readdir    = ramdisc_readdir,
    .open       = ramdisc_open,
    .create     = ramdisc_create,
    .read       = ramdisc_read,
    .write      = ramdisc_write,
    .release    = ramdisc_release,
    .unlink     = ramdisc_unlink,
    .mkdir      = ramdisc_mkdir,
    .rmdir      = ramdisc_rmdir,
    .rename     = ramdisc_rename,
    .truncate   = ramdisc_truncate,
    .ftruncate  = ramdisc_ftruncate,
    .fsync      = ramdisc_fsync,
};

struct ramdisc_config {
    size_t size_mb;
    char *backing_path;
};

#define RAMDISC_OPT(t, p, v) { t, offsetof(struct ramdisc_config, p), v }

static struct fuse_opt ramdisc_opts[] = {
    RAMDISC_OPT("size=%zu", size_mb, 0),
    RAMDISC_OPT("backing=%s", backing_path, 0),
    FUSE_OPT_END
};

static void *ramdisc_init(struct fuse_conn_info *conn) {
    (void)conn;
    return NULL;
}

static void ramdisc_destroy(void *private_data) {
    (void)private_data;
    
    if (g_device) {
        rd_unmount(g_device);
        rd_destroy(g_device);
        g_device = NULL;
    }
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct ramdisc_config config = {
        .size_mb = 64,  /* Default 64 MB */
        .backing_path = NULL,
    };
    
    /* Parse options */
    if (fuse_opt_parse(&args, &config, ramdisc_opts, NULL) == -1) {
        return 1;
    }
    
    /* Create ramdisc device */
    size_t size_bytes = config.size_mb * 1024 * 1024;
    unsigned flags = 0;
    
    if (config.backing_path) {
        flags |= RD_BACKING_CREATE | RD_BACKING_TRUNC;
    }
    
    g_device = rd_create(size_bytes, 4096, config.backing_path, flags);
    if (!g_device) {
        fprintf(stderr, "Failed to create ramdisc device\n");
        return 1;
    }
    
    int ret = rd_mount(g_device);
    if (ret < 0) {
        fprintf(stderr, "Failed to mount ramdisc: %d\n", ret);
        rd_destroy(g_device);
        return 1;
    }
    
    /* Update operations with init/destroy */
    ramdisc_oper.init = ramdisc_init;
    ramdisc_oper.destroy = ramdisc_destroy;
    
    /* Run FUSE */
    ret = fuse_main(args.argc, args.argv, &ramdisc_oper, NULL);
    
    fuse_opt_free_args(&args);
    free(config.backing_path);
    
    return ret;
}
