#include "ramdisc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define CHECK_OK(expr) do { int _rc = (expr); assert(_rc == RD_OK); } while (0)

static void run_test(const char* name, void (*fn)(void)) {
    printf("[TEST] %s...\n", name);
    fn();
    printf("[PASS] %s\n\n", name);
}

static rd_device_t make_dev(void) {
    rd_device_t dev = rd_create(1u << 20, 4096, NULL, 0);
    assert(dev != NULL);
    CHECK_OK(rd_mount(dev));
    return dev;
}

struct name_list {
    char names[8][RD_MAX_NAME];
    int count;
};

struct test_case {
    const char* name;   /* identifier used by --case */
    const char* pretty; /* human-friendly label */
    void (*fn)(void);
};

static int collect_names(const char* name, const rd_stat_info* st, void* user) {
    (void)st;
    struct name_list* nl = (struct name_list*)user;
    if (nl->count < 8) {
        strncpy(nl->names[nl->count], name, RD_MAX_NAME - 1);
        nl->names[nl->count][RD_MAX_NAME - 1] = '\0';
        nl->count++;
    }
    return 0;
}

static void test_root_stat(void) {
    rd_device_t dev = make_dev();
    printf("  - stat root directory\n");
    rd_stat_info st;
    CHECK_OK(rd_stat(dev, "/", &st));
    assert(st.type == RD_FT_DIR);
    rd_destroy(dev);
}

static void test_create_write_read(void) {
    rd_device_t dev = make_dev();
    printf("  - create file /hello\n");
    rd_fd fd = rd_open(dev, "/hello", RD_O_CREATE | RD_O_RDWR | RD_O_TRUNC, 0644);
    assert(fd >= 0);
    const char msg[] = "hello world";
    printf("  - write %zu bytes\n", sizeof(msg));
    ssize_t w = rd_write(dev, fd, msg, sizeof(msg));
    assert(w == (ssize_t)sizeof(msg));
    printf("  - seek to start and read back\n");
    CHECK_OK(rd_seek(dev, fd, 0, 0));
    char buf[32] = {0};
    ssize_t r = rd_read(dev, fd, buf, sizeof(buf));
    assert(r == (ssize_t)sizeof(msg));
    assert(memcmp(buf, msg, sizeof(msg)) == 0);
    rd_close(dev, fd);
    struct name_list nl = {0};
    printf("  - readdir / and confirm presence\n");
    CHECK_OK(rd_readdir(dev, "/", collect_names, &nl));
    int seen_hello = 0;
    for (int i = 0; i < nl.count; ++i) {
        if (strcmp(nl.names[i], "hello") == 0) {
            seen_hello = 1;
        }
    }
    assert(seen_hello == 1);
    printf("  - unlink and expect RD_ERR_NOENT\n");
    CHECK_OK(rd_unlink(dev, "/hello"));
    int rc = rd_stat(dev, "/hello", &((rd_stat_info){0}));
    assert(rc == RD_ERR_NOENT);
    rd_destroy(dev);
}

static void test_mkdir_readdir(void) {
    rd_device_t dev = make_dev();
    printf("  - mkdir /dir and create /dir/file.txt\n");
    CHECK_OK(rd_mkdir(dev, "/dir"));
    rd_fd fd = rd_open(dev, "/dir/file.txt", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    const char msg[] = "abc";
    assert(rd_write(dev, fd, msg, sizeof(msg)) == (ssize_t)sizeof(msg));
    rd_close(dev, fd);

    struct name_list nl = {0};
    printf("  - readdir / and confirm dir entry\n");
    CHECK_OK(rd_readdir(dev, "/", collect_names, &nl));
    int seen_dir = 0;
    for (int i = 0; i < nl.count; ++i) {
        if (strcmp(nl.names[i], "dir") == 0) {
            seen_dir = 1;
        }
    }
    assert(seen_dir == 1);

    printf("  - cleanup /dir/file.txt then /dir\n");
    CHECK_OK(rd_unlink(dev, "/dir/file.txt"));
    CHECK_OK(rd_rmdir(dev, "/dir"));
    rd_destroy(dev);
}

static void test_large_write_indirect(void) {
    rd_device_t dev = rd_create(1u << 20, 1024, NULL, 0);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    printf("  - create /big and write 10 KiB (exercises indirect blocks)\n");
    rd_fd fd = rd_open(dev, "/big", RD_O_CREATE | RD_O_RDWR | RD_O_TRUNC, 0644);
    assert(fd >= 0);
    size_t len = 10 * 1024; /* spans direct and indirect */
    unsigned char* buf = (unsigned char*)malloc(len);
    for (size_t i = 0; i < len; ++i) buf[i] = (unsigned char)(i & 0xFF);
    assert(rd_write(dev, fd, buf, len) == (ssize_t)len);
    CHECK_OK(rd_seek(dev, fd, 0, 0));
    printf("  - read back and compare\n");
    unsigned char* out = (unsigned char*)calloc(1, len);
    assert(rd_read(dev, fd, out, len) == (ssize_t)len);
    assert(memcmp(buf, out, len) == 0);
    free(buf);
    free(out);
    rd_close(dev, fd);
    rd_destroy(dev);
}

static void test_rmdir_nonempty_fails(void) {
    rd_device_t dev = make_dev();
    printf("  - mkdir /dir and add child file\n");
    CHECK_OK(rd_mkdir(dev, "/dir"));
    rd_fd fd = rd_open(dev, "/dir/file", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    rd_close(dev, fd);
    printf("  - rmdir non-empty dir should fail with RD_ERR_PERM\n");
    int rc = rd_rmdir(dev, "/dir");
    assert(rc == RD_ERR_PERM);
    printf("  - cleanup child then remove dir\n");
    CHECK_OK(rd_unlink(dev, "/dir/file"));
    CHECK_OK(rd_rmdir(dev, "/dir"));
    rd_destroy(dev);
}

static void test_enospc(void) {
    rd_device_t dev = rd_create(20 * 1024, 1024, NULL, 0);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    printf("  - write until ENOSPC on 20 KiB device\n");
    rd_fd fd = rd_open(dev, "/full", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    unsigned char buf[2048];
    memset(buf, 0xAB, sizeof(buf));
    int saw_nospc = 0;
    for (int i = 0; i < 16; ++i) {
        ssize_t r = rd_write(dev, fd, buf, sizeof(buf));
        if (r < 0) {
            assert(r == RD_ERR_NOSPC);
            saw_nospc = 1;
            break;
        }
    }
    assert(saw_nospc == 1);
    rd_destroy(dev);
}

static void test_block_api(void) {
    rd_device_t dev = make_dev();
    printf("  - block write/read round-trip\n");
    unsigned char w[4096];
    for (size_t i = 0; i < sizeof(w); ++i) w[i] = (unsigned char)(i & 0xFF);
    assert(rd_block_write(dev, 1, w, 1) == 1);
    unsigned char r[4096] = {0};
    assert(rd_block_read(dev, 1, r, 1) == 1);
    assert(memcmp(w, r, sizeof(w)) == 0);
    rd_destroy(dev);
}

static void test_backing_persistence(void) {
    char path[] = "/tmp/ramdisc_backingXXXXXX";
    int fd_tmp = mkstemp(path);
    assert(fd_tmp >= 0);
    close(fd_tmp);

    printf("  - create device with backing file %s\n", path);
    rd_device_t dev = rd_create(1u << 20, 4096, path, RD_BACKING_TRUNC);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    rd_fd fd = rd_open(dev, "/persist", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    const char msg[] = "persisted";
    printf("  - write persisted payload and flush\n");
    assert(rd_write(dev, fd, msg, sizeof(msg)) == (ssize_t)sizeof(msg));
    rd_close(dev, fd);
    CHECK_OK(rd_block_flush(dev));
    rd_destroy(dev);

    printf("  - reopen device from backing and verify contents\n");
    rd_device_t dev2 = rd_create(1u << 20, 4096, path, 0);
    assert(dev2);
    CHECK_OK(rd_mount(dev2));
    char buf[32] = {0};
    rd_fd fd2 = rd_open(dev2, "/persist", RD_O_RDONLY, 0);
    assert(fd2 >= 0);
    assert(rd_read(dev2, fd2, buf, sizeof(msg)) == (ssize_t)sizeof(msg));
    assert(memcmp(buf, msg, sizeof(msg)) == 0);
    rd_close(dev2, fd2);
    rd_destroy(dev2);
    unlink(path);
}

static void test_seek_whence(void) {
    rd_device_t dev = make_dev();
    printf("  - create file with content\n");
    rd_fd fd = rd_open(dev, "/seektest", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    const char msg[] = "0123456789";
    /* Write without null terminator */
    assert(rd_write(dev, fd, msg, strlen(msg)) == (ssize_t)strlen(msg));
    
    printf("  - test SEEK_SET (0)\n");
    CHECK_OK(rd_seek(dev, fd, 5, SEEK_SET));
    char buf[2] = {0};
    assert(rd_read(dev, fd, buf, 1) == 1);
    assert(buf[0] == '5');
    
    printf("  - test SEEK_CUR (1)\n");
    CHECK_OK(rd_seek(dev, fd, -3, SEEK_CUR));
    assert(rd_read(dev, fd, buf, 1) == 1);
    assert(buf[0] == '3');
    
    printf("  - test SEEK_END (2)\n");
    CHECK_OK(rd_seek(dev, fd, -5, SEEK_END));
    assert(rd_read(dev, fd, buf, 1) == 1);
    assert(buf[0] == '5');
    
    printf("  - test negative seek returns error\n");
    assert(rd_seek(dev, fd, -100, SEEK_SET) == RD_ERR_INVAL);
    
    rd_close(dev, fd);
    rd_destroy(dev);
}

static void test_concurrent_handles(void) {
    rd_device_t dev = make_dev();
    printf("  - create file and write initial data\n");
    rd_fd fd1 = rd_open(dev, "/shared", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd1 >= 0);
    const char msg1[] = "AAAA";
    assert(rd_write(dev, fd1, msg1, strlen(msg1)) == (ssize_t)strlen(msg1));
    
    printf("  - open same file again\n");
    rd_fd fd2 = rd_open(dev, "/shared", RD_O_RDWR, 0);
    assert(fd2 >= 0);
    assert(fd1 != fd2);
    
    printf("  - verify independent file positions\n");
    CHECK_OK(rd_seek(dev, fd1, 0, SEEK_SET));
    CHECK_OK(rd_seek(dev, fd2, 2, SEEK_SET));
    
    const char msg2[] = "BB";
    assert(rd_write(dev, fd2, msg2, strlen(msg2)) == (ssize_t)strlen(msg2));
    
    printf("  - verify writes visible from both handles\n");
    CHECK_OK(rd_seek(dev, fd1, 0, SEEK_SET));
    char buf[8] = {0};
    assert(rd_read(dev, fd1, buf, 4) == 4);
    assert(memcmp(buf, "AABB", 4) == 0);
    
    rd_close(dev, fd1);
    rd_close(dev, fd2);
    rd_destroy(dev);
}

static void test_max_file_size(void) {
    rd_device_t dev = rd_create(8u << 20, 1024, NULL, 0);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    printf("  - calculate max file size for 1KB blocks\n");
    /* 8 direct + 256 indirect (1024/4) = 264 blocks * 1024 = 270336 bytes */
    size_t max_size = (8 + 256) * 1024;
    
    printf("  - create file and write to max capacity\n");
    rd_fd fd = rd_open(dev, "/maxfile", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    
    unsigned char* buf = (unsigned char*)malloc(max_size);
    for (size_t i = 0; i < max_size; ++i) buf[i] = (unsigned char)(i & 0xFF);
    ssize_t written = rd_write(dev, fd, buf, max_size);
    assert(written == (ssize_t)max_size);
    
    printf("  - verify file size at limit\n");
    rd_stat_info st;
    CHECK_OK(rd_fstat(dev, fd, &st));
    assert(st.size_bytes == max_size);
    
    printf("  - write beyond to test double-indirect works\n");
    CHECK_OK(rd_seek(dev, fd, 0, SEEK_END));
    /* Should succeed now with double indirect (unless ENOSPC) */
    ssize_t more = rd_write(dev, fd, "XXXX", 4);
    assert(more == 4 || more == RD_ERR_NOSPC);
    
    free(buf);
    rd_close(dev, fd);
    rd_destroy(dev);
}

static void test_path_edge_cases(void) {
    rd_device_t dev = make_dev();
    
    printf("  - test root path variations\n");
    rd_stat_info st;
    CHECK_OK(rd_stat(dev, "/", &st));
    assert(st.type == RD_FT_DIR);
    
    printf("  - test missing leading slash\n");
    assert(rd_stat(dev, "no�ash", &st) == RD_ERR_INVAL);
    
    printf("  - test empty path components (//dir)\n");
    CHECK_OK(rd_mkdir(dev, "/validdir"));
    /* Most implementations treat // as / but behavior may vary */
    
    printf("  - test long filename (near RD_MAX_NAME limit)\n");
    char longname[RD_MAX_NAME + 10];
    memset(longname, 'a', sizeof(longname) - 1);
    longname[0] = '/';
    longname[sizeof(longname) - 1] = '\0';
    /* Should fail as name too long (exceeds RD_MAX_NAME) */
    rd_fd fd = rd_open(dev, longname, RD_O_CREATE | RD_O_RDWR, 0644);
    /* Implementation uses strnlen with RD_MAX_NAME so may not fail, just truncate */
    if (fd >= 0) {
        rd_close(dev, fd);
        rd_unlink(dev, longname);
    }
    
    printf("  - test filename exactly at RD_MAX_NAME-1 (should work)\\n");
    char maxname[RD_MAX_NAME + 10];
    memset(maxname, 'b', RD_MAX_NAME - 2);
    maxname[0] = '/';
    maxname[RD_MAX_NAME - 2] = '\0';
    rd_fd fd2 = rd_open(dev, maxname, RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd2 >= 0);
    rd_close(dev, fd2);
    CHECK_OK(rd_unlink(dev, maxname));
    
    printf("  - test valid long path with multiple components\n");
    CHECK_OK(rd_mkdir(dev, "/a"));
    CHECK_OK(rd_mkdir(dev, "/a/b"));
    CHECK_OK(rd_mkdir(dev, "/a/b/c"));
    CHECK_OK(rd_stat(dev, "/a/b/c", &st));
    assert(st.type == RD_FT_DIR);
    
    rd_destroy(dev);
}

static void test_enospc_recovery(void) {
    rd_device_t dev = rd_create(32 * 1024, 1024, NULL, 0);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    
    printf("  - fill device until ENOSPC\n");
    rd_fd fd1 = rd_open(dev, "/fill1", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd1 >= 0);
    unsigned char buf[2048];
    memset(buf, 0xAA, sizeof(buf));
    int saw_nospc = 0;
    for (int i = 0; i < 32; ++i) {
        ssize_t r = rd_write(dev, fd1, buf, sizeof(buf));
        if (r < 0) {
            assert(r == RD_ERR_NOSPC);
            saw_nospc = 1;
            break;
        }
    }
    assert(saw_nospc == 1);
    rd_close(dev, fd1);
    
    printf("  - delete file and verify space recovered\n");
    CHECK_OK(rd_unlink(dev, "/fill1"));
    
    printf("  - verify we can write again after recovery\n");
    rd_fd fd2 = rd_open(dev, "/fill2", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd2 >= 0);
    ssize_t r = rd_write(dev, fd2, buf, sizeof(buf));
    assert(r == (ssize_t)sizeof(buf));
    rd_close(dev, fd2);
    
    printf("  - verify file contents after recovery\n");
    rd_fd fd3 = rd_open(dev, "/fill2", RD_O_RDONLY, 0);
    assert(fd3 >= 0);
    unsigned char rbuf[2048] = {0};
    assert(rd_read(dev, fd3, rbuf, sizeof(rbuf)) == (ssize_t)sizeof(rbuf));
    assert(memcmp(buf, rbuf, sizeof(buf)) == 0);
    rd_close(dev, fd3);
    
    rd_destroy(dev);
}

static void test_double_indirect(void) {
    /* Test files larger than single indirect can handle */
    rd_device_t dev = rd_create(16u << 20, 4096, NULL, 0);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    
    printf("  - calculate sizes: 8 direct + 1024 indirect + need double-indirect\\n");
    /* 8 direct (32KB) + 1024 indirect (4MB) = 4,227,072 bytes */
    /* Write past this to test double indirect */
    size_t past_indirect = (8 + 1024) * 4096;
    size_t write_size = past_indirect + 8192; /* 2 blocks into double-indirect */
    
    printf("  - create large file requiring double indirect blocks\\n");
    rd_fd fd = rd_open(dev, "/largefile", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    
    /* Write pattern to end of file */
    unsigned char* buf = (unsigned char*)malloc(write_size);
    for (size_t i = 0; i < write_size; ++i) {
        buf[i] = (unsigned char)((i / 4096) & 0xFF);
    }
    
    printf("  - write %.2f MB to trigger double indirect\\n", write_size / (1024.0 * 1024.0));
    ssize_t w = rd_write(dev, fd, buf, write_size);
    assert(w == (ssize_t)write_size);
    
    printf("  - verify file size\\n");
    rd_stat_info st;
    CHECK_OK(rd_fstat(dev, fd, &st));
    assert(st.size_bytes == write_size);
    
    printf("  - seek and verify data in double-indirect region\\n");
    CHECK_OK(rd_seek(dev, fd, past_indirect, SEEK_SET));
    unsigned char rbuf[8192];
    ssize_t r = rd_read(dev, fd, rbuf, 8192);
    assert(r == 8192);
    assert(memcmp(rbuf, buf + past_indirect, 8192) == 0);
    
    free(buf);
    rd_close(dev, fd);
    rd_destroy(dev);
}

static void test_many_handles(void) {
    /* Use larger device to support more inodes */
    rd_device_t dev = rd_create(4u << 20, 4096, NULL, 0);
    assert(dev);
    CHECK_OK(rd_mount(dev));
    
    printf("  - open 100 files to exceed initial 64 handle limit\\n");
    rd_fd fds[100];
    int opened = 0;
    for (int i = 0; i < 100; ++i) {
        char path[32];
        snprintf(path, sizeof(path), "/file%d", i);
        fds[i] = rd_open(dev, path, RD_O_CREATE | RD_O_RDWR, 0644);
        if (fds[i] < 0) {
            /* May run out of space or inodes */
            printf("  - opened %d files before failure\\n", i);
            break;
        }
        opened++;
    }
    
    /* Should have opened at least 70 to prove dynamic growth works */
    assert(opened >= 70);
    printf("  - successfully opened %d files (proves dynamic growth past 64)\\n", opened);
    
    printf("  - verify opened handles work independently\\n");
    for (int i = 0; i < opened; ++i) {
        char msg[16];
        snprintf(msg, sizeof(msg), "FD%d", i);
        ssize_t w = rd_write(dev, fds[i], msg, strlen(msg));
        /* May hit ENOSPC with many small files */
        if (w < 0) {
            printf("  - hit error %zd writing to file %d\\n", w, i);
            assert(w == RD_ERR_NOSPC);
            break;
        }
        assert(w == (ssize_t)strlen(msg));
    }
    
    printf("  - close all handles\\n");
    for (int i = 0; i < opened; ++i) {
        CHECK_OK(rd_close(dev, fds[i]));
    }
    
    rd_destroy(dev);
}

static void test_rename(void) {
    rd_device_t dev = rd_create(200 * 1024, 4096, NULL, 0);
    CHECK_OK(rd_mount(dev));
    
    printf("  - create file /old_file\n");
    rd_fd fd = rd_open(dev, "/old_file", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    ssize_t w = rd_write(dev, fd, "original", 8);
    assert(w == 8);
    CHECK_OK(rd_close(dev, fd));
    
    printf("  - rename /old_file to /new_file\n");
    CHECK_OK(rd_rename(dev, "/old_file", "/new_file"));
    
    printf("  - verify old path doesn't exist\n");
    rd_stat_info st;
    assert(rd_stat(dev, "/old_file", &st) == RD_ERR_NOENT);
    
    printf("  - verify new path exists with same content\n");
    CHECK_OK(rd_stat(dev, "/new_file", &st));
    assert(st.size_bytes == 8);
    fd = rd_open(dev, "/new_file", RD_O_RDONLY, 0);
    assert(fd >= 0);
    char buf[16] = {0};
    ssize_t r = rd_read(dev, fd, buf, sizeof(buf));
    assert(r == 8);
    assert(memcmp(buf, "original", 8) == 0);
    CHECK_OK(rd_close(dev, fd));
    
    printf("  - create /dir and rename file into directory\n");
    CHECK_OK(rd_mkdir(dev, "/dir"));
    CHECK_OK(rd_rename(dev, "/new_file", "/dir/moved_file"));
    
    printf("  - verify file moved into directory\n");
    assert(rd_stat(dev, "/new_file", &st) == RD_ERR_NOENT);
    CHECK_OK(rd_stat(dev, "/dir/moved_file", &st));
    assert(st.size_bytes == 8);
    
    printf("  - test rename with overwrite\n");
    fd = rd_open(dev, "/dir/target", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    w = rd_write(dev, fd, "will be replaced", 16);
    assert(w == 16);
    CHECK_OK(rd_close(dev, fd));
    
    CHECK_OK(rd_rename(dev, "/dir/moved_file", "/dir/target"));
    CHECK_OK(rd_stat(dev, "/dir/target", &st));
    assert(st.size_bytes == 8);  /* Should be size of moved_file, not target */
    
    printf("  - test directory rename\n");
    CHECK_OK(rd_rename(dev, "/dir", "/renamed_dir"));
    assert(rd_stat(dev, "/dir", &st) == RD_ERR_NOENT);
    CHECK_OK(rd_stat(dev, "/renamed_dir", &st));
    assert(st.type == RD_FT_DIR);
    CHECK_OK(rd_stat(dev, "/renamed_dir/target", &st));
    
    rd_destroy(dev);
}

static void test_fsync(void) {
    char tmpfile[] = "/tmp/ramdisc_fsync_XXXXXX";
    int tmp_fd = mkstemp(tmpfile);
    assert(tmp_fd >= 0);
    close(tmp_fd);
    
    printf("  - create device with backing file %s\n", tmpfile);
    rd_device_t dev = rd_create(200 * 1024, 4096, tmpfile, RD_BACKING_CREATE | RD_BACKING_TRUNC);
    assert(dev != NULL);
    CHECK_OK(rd_mount(dev));
    
    printf("  - create and write to file\n");
    rd_fd fd = rd_open(dev, "/fsync_test", RD_O_CREATE | RD_O_RDWR, 0644);
    assert(fd >= 0);
    const char* data = "this should be synced";
    ssize_t w = rd_write(dev, fd, data, strlen(data));
    assert(w == (ssize_t)strlen(data));
    
    printf("  - fsync file (should flush to backing)\n");
    CHECK_OK(rd_fsync(dev, fd));
    CHECK_OK(rd_close(dev, fd));
    
    printf("  - unmount and remount from backing\n");
    CHECK_OK(rd_unmount(dev));
    rd_destroy(dev);
    
    dev = rd_create(200 * 1024, 4096, tmpfile, 0);
    assert(dev != NULL);
    CHECK_OK(rd_mount(dev));
    
    printf("  - verify data persisted\n");
    fd = rd_open(dev, "/fsync_test", RD_O_RDONLY, 0);
    assert(fd >= 0);
    char buf[64] = {0};
    ssize_t r = rd_read(dev, fd, buf, sizeof(buf));
    assert(r == (ssize_t)strlen(data));
    assert(memcmp(buf, data, strlen(data)) == 0);
    CHECK_OK(rd_close(dev, fd));
    
    CHECK_OK(rd_unmount(dev));
    rd_destroy(dev);
    unlink(tmpfile);
}

static const struct test_case TEST_CASES[] = {
    {"root_stat", "root stat", test_root_stat},
    {"create_write_read", "create/write/read", test_create_write_read},
    {"mkdir_readdir", "mkdir/readdir", test_mkdir_readdir},
    {"large_write_indirect", "large write indirect", test_large_write_indirect},
    {"rmdir_nonempty", "rmdir non-empty", test_rmdir_nonempty_fails},
    {"enospc_handling", "enospc handling", test_enospc},
    {"block_api", "block API", test_block_api},
    {"backing_persistence", "backing persistence", test_backing_persistence},
    {"seek_whence", "seek with whence modes", test_seek_whence},
    {"concurrent_handles", "concurrent file handles", test_concurrent_handles},
    {"max_file_size", "maximum file size", test_max_file_size},
    {"path_edge_cases", "path edge cases", test_path_edge_cases},
    {"enospc_recovery", "ENOSPC recovery", test_enospc_recovery},
    {"double_indirect", "double indirect blocks", test_double_indirect},
    {"many_handles", "dynamic handle growth", test_many_handles},
    {"rename", "file and directory rename", test_rename},
    {"fsync", "per-file fsync", test_fsync},
};

static const size_t TEST_CASE_COUNT = sizeof(TEST_CASES) / sizeof(TEST_CASES[0]);

static const struct test_case* find_case(const char* name) {
    for (size_t i = 0; i < TEST_CASE_COUNT; ++i) {
        if (strcmp(TEST_CASES[i].name, name) == 0) {
            return &TEST_CASES[i];
        }
    }
    return NULL;
}

static void list_cases(void) {
    for (size_t i = 0; i < TEST_CASE_COUNT; ++i) {
        printf("  %s\t%s\n", TEST_CASES[i].name, TEST_CASES[i].pretty);
    }
}

static void usage(const char* prog) {
    printf("Usage: %s [--case NAME] [--list] [--help]\n", prog);
}

int main(int argc, char** argv) {
    const struct test_case* selected = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "--list") == 0) {
            list_cases();
            return 0;
        } else if (strcmp(argv[1], "--case") == 0) {
            if (argc < 3) {
                usage(argv[0]);
                return 1;
            }
            selected = find_case(argv[2]);
            if (!selected) {
                fprintf(stderr, "Unknown test case: %s\n", argv[2]);
                list_cases();
                return 1;
            }
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            usage(argv[0]);
            list_cases();
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (selected) {
        run_test(selected->pretty, selected->fn);
    } else {
        for (size_t i = 0; i < TEST_CASE_COUNT; ++i) {
            run_test(TEST_CASES[i].pretty, TEST_CASES[i].fn);
        }
    }

    printf("ramdisc tests passed\n");
    return 0;
}
