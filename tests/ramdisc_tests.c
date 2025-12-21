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

static const struct test_case TEST_CASES[] = {
    {"root_stat", "root stat", test_root_stat},
    {"create_write_read", "create/write/read", test_create_write_read},
    {"mkdir_readdir", "mkdir/readdir", test_mkdir_readdir},
    {"large_write_indirect", "large write indirect", test_large_write_indirect},
    {"rmdir_nonempty", "rmdir non-empty", test_rmdir_nonempty_fails},
    {"enospc_handling", "enospc handling", test_enospc},
    {"block_api", "block API", test_block_api},
    {"backing_persistence", "backing persistence", test_backing_persistence},
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
