#include "ramdisc.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#define RD_MAGIC 0x52444953u
#define RD_VERSION 1u
#define RD_MAX_DIRECT 8
#define RD_MAX_INDIRECT_ENTRIES(block_sz) ((block_sz) / sizeof(uint32_t))
#define RD_MAX_HANDLES 64
#define RD_MAX_PATH_SEGS 32
#define RD_MAX_NAME 64

struct rd_superblock {
    uint32_t magic;
    uint32_t version;
    uint32_t block_size;
    uint32_t block_count;
    uint32_t inode_count;
    uint32_t free_blocks;
    uint32_t free_inodes;
    uint32_t bitmap_start;
    uint32_t inode_start;
    uint32_t data_start;
    uint32_t root_inode;
    uint32_t free_block_head;  /* Head of free block linked list (0 = empty) */
    uint32_t free_inode_head;  /* Head of free inode linked list (0 = empty) */
};

struct rd_inode {
    uint16_t mode;
    uint8_t type; /* rd_file_type */
    uint8_t reserved0;
    uint32_t links;
    uint64_t size;
    uint32_t blocks[RD_MAX_DIRECT];
    uint32_t indirect;
    uint32_t double_indirect;
    uint32_t next_free;  /* Next inode in free list (was reserved1) */
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
};

struct rd_dirent_disk {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[];
};

struct rd_handle {
    int used;
    uint32_t inode_idx;
    size_t offset;
    unsigned flags;
};

struct rd_device {
    unsigned char* data;
    size_t size_bytes;
    size_t block_size;
    char* backing_path;
    FILE* backing_file;
    int backing_present;
    struct rd_handle* handles;
    size_t handle_capacity;
    unsigned char* dirty_bitmap;
    pthread_rwlock_t fs_lock;    /* Protects filesystem structures (superblock, bitmap, inodes, dirs) */
    pthread_mutex_t handle_lock;  /* Protects handle table */
};

static void rd_free_aligned(void* ptr) {
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

static void* rd_alloc_aligned(size_t size, size_t alignment) {
#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#else
    void* mem = NULL;
    if (posix_memalign(&mem, alignment, size) != 0) {
        return NULL;
    }
    return mem;
#endif
}

static uint64_t rd_now_ns(void) {
#if defined(_WIN32)
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.HighPart = ft.dwHighDateTime;
    uli.LowPart = ft.dwLowDateTime;
    return (uli.QuadPart - 116444736000000000ULL) * 100;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static struct rd_superblock* rd_sb(rd_device_t dev) {
    return (struct rd_superblock*)dev->data;
}

static struct rd_inode* rd_inode_base(rd_device_t dev) {
    struct rd_superblock* sb = rd_sb(dev);
    return (struct rd_inode*)(dev->data + sb->inode_start * dev->block_size);
}

static struct rd_inode* rd_inode_get(rd_device_t dev, uint32_t idx) {
    struct rd_superblock* sb = rd_sb(dev);
    if (idx >= sb->inode_count) {
        return NULL;
    }
    return rd_inode_base(dev) + idx;
}

static unsigned char* rd_block_ptr(rd_device_t dev, uint32_t block_idx) {
    struct rd_superblock* sb = rd_sb(dev);
    if (block_idx >= sb->block_count) {
        return NULL;
    }
    return dev->data + (size_t)block_idx * dev->block_size;
}

static int rd_bitmap_test(rd_device_t dev, uint32_t block_idx) {
    struct rd_superblock* sb = rd_sb(dev);
    uint32_t byte = block_idx / 8;
    uint32_t bit = block_idx % 8;
    unsigned char* bm = rd_block_ptr(dev, sb->bitmap_start);
    return (bm[byte] >> bit) & 1u;
}

static void rd_bitmap_set(rd_device_t dev, uint32_t block_idx, int value) {
    struct rd_superblock* sb = rd_sb(dev);
    uint32_t byte = block_idx / 8;
    uint32_t bit = block_idx % 8;
    unsigned char* bm = rd_block_ptr(dev, sb->bitmap_start);
    if (value) {
        bm[byte] |= (unsigned char)(1u << bit);
    } else {
        bm[byte] &= (unsigned char)~(1u << bit);
    }
}

static void rd_mark_dirty(rd_device_t dev, uint32_t block_idx) {
    if (!dev->dirty_bitmap) {
        return;
    }
    struct rd_superblock* sb = rd_sb(dev);
    if (block_idx >= sb->block_count) {
        return;
    }
    uint32_t byte = block_idx / 8;
    uint32_t bit = block_idx % 8;
    dev->dirty_bitmap[byte] |= (unsigned char)(1u << bit);
}

static int rd_is_dirty(rd_device_t dev, uint32_t block_idx) {
    if (!dev->dirty_bitmap) {
        return 1; /* Assume dirty if no tracking */
    }
    struct rd_superblock* sb = rd_sb(dev);
    if (block_idx >= sb->block_count) {
        return 0;
    }
    uint32_t byte = block_idx / 8;
    uint32_t bit = block_idx % 8;
    return (dev->dirty_bitmap[byte] >> bit) & 1u;
}

static void rd_clear_dirty(rd_device_t dev, uint32_t block_idx) {
    if (!dev->dirty_bitmap) {
        return;
    }
    struct rd_superblock* sb = rd_sb(dev);
    if (block_idx >= sb->block_count) {
        return;
    }
    uint32_t byte = block_idx / 8;
    uint32_t bit = block_idx % 8;
    dev->dirty_bitmap[byte] &= (unsigned char)~(1u << bit);
}

static int rd_block_alloc(rd_device_t dev) {
    struct rd_superblock* sb = rd_sb(dev);
    if (sb->free_blocks == 0) {
        return RD_ERR_NOSPC;
    }
    
    /* Pop from free list head */
    uint32_t block_idx = sb->free_block_head;
    if (block_idx == 0) {
        /* Fallback to linear search if free list not initialized */
        uint32_t total = sb->block_count;
        unsigned char* bm = rd_block_ptr(dev, sb->bitmap_start);
        uint32_t bm_bytes = (total + 7u) / 8u;
        for (uint32_t i = sb->data_start; i < total; ++i) {
            uint32_t byte = i / 8;
            uint32_t bit = i % 8;
            if (byte >= bm_bytes) {
                break;
            }
            if ((bm[byte] & (1u << bit)) == 0) {
                rd_bitmap_set(dev, i, 1);
                sb->free_blocks--;
                memset(rd_block_ptr(dev, i), 0, dev->block_size);
                rd_mark_dirty(dev, i);
                return (int)i;
            }
        }
        return RD_ERR_NOSPC;
    }
    
    /* Read next pointer from free block */
    uint32_t* block_data = (uint32_t*)rd_block_ptr(dev, block_idx);
    uint32_t next_free = block_data[0];
    
    /* Update free list head */
    sb->free_block_head = next_free;
    sb->free_blocks--;
    
    /* Mark as allocated and clear */
    rd_bitmap_set(dev, block_idx, 1);
    memset(rd_block_ptr(dev, block_idx), 0, dev->block_size);
    rd_mark_dirty(dev, block_idx);
    
    return (int)block_idx;
}

static void rd_block_free(rd_device_t dev, uint32_t block_idx) {
    struct rd_superblock* sb = rd_sb(dev);
    if (block_idx < sb->data_start || block_idx >= sb->block_count) {
        return;
    }
    if (rd_bitmap_test(dev, block_idx)) {
        rd_bitmap_set(dev, block_idx, 0);
        sb->free_blocks++;
        
        /* Add to head of free list */
        uint32_t* block_data = (uint32_t*)rd_block_ptr(dev, block_idx);
        block_data[0] = sb->free_block_head;
        sb->free_block_head = block_idx;
        rd_mark_dirty(dev, block_idx);
    }
}

static int rd_inode_alloc(rd_device_t dev) {
    struct rd_superblock* sb = rd_sb(dev);
    if (sb->free_inodes == 0) {
        return RD_ERR_NOSPC;
    }
    
    /* Pop from free list head */
    uint32_t inode_idx = sb->free_inode_head;
    if (inode_idx == 0) {
        /* Fallback to linear search if free list not initialized */
        struct rd_inode* base = rd_inode_base(dev);
        for (uint32_t i = 0; i < sb->inode_count; ++i) {
            if (base[i].type == RD_FT_UNKNOWN && base[i].links == 0) {
                sb->free_inodes--;
                return (int)i;
            }
        }
        return RD_ERR_NOSPC;
    }
    
    /* Get inode and update free list */
    struct rd_inode* in = rd_inode_get(dev, inode_idx);
    if (!in) {
        return RD_ERR_IO;
    }
    
    uint32_t next_free = in->next_free;
    sb->free_inode_head = next_free;
    sb->free_inodes--;
    
    return (int)inode_idx;
}

static void rd_inode_free(rd_device_t dev, uint32_t idx) {
    struct rd_superblock* sb = rd_sb(dev);
    if (idx >= sb->inode_count) {
        return;
    }
    struct rd_inode* in = rd_inode_get(dev, idx);
    if (!in) {
        return;
    }
    /* Free double indirect blocks */
    if (in->double_indirect) {
        uint32_t* di_table = (uint32_t*)rd_block_ptr(dev, in->double_indirect);
        size_t di_limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
        for (size_t i = 0; i < di_limit; ++i) {
            if (di_table[i]) {
                uint32_t* table = (uint32_t*)rd_block_ptr(dev, di_table[i]);
                size_t limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
                for (size_t j = 0; j < limit; ++j) {
                    if (table[j]) {
                        rd_block_free(dev, table[j]);
                    }
                }
                rd_block_free(dev, di_table[i]);
            }
        }
        rd_block_free(dev, in->double_indirect);
        in->double_indirect = 0;
    }
    /* Free indirect blocks */
    if (in->indirect) {
        uint32_t* table = (uint32_t*)rd_block_ptr(dev, in->indirect);
        size_t limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
        for (size_t i = 0; i < limit; ++i) {
            if (table[i]) {
                rd_block_free(dev, table[i]);
            }
        }
        rd_block_free(dev, in->indirect);
        in->indirect = 0;
    }
    /* Free direct blocks */
    for (size_t i = 0; i < RD_MAX_DIRECT; ++i) {
        if (in->blocks[i]) {
            rd_block_free(dev, in->blocks[i]);
            in->blocks[i] = 0;
        }
    }
    memset(in, 0, sizeof(*in));
    
    /* Add to head of free inode list */
    in->next_free = sb->free_inode_head;
    sb->free_inode_head = idx;
    sb->free_inodes++;
}

static int rd_inode_get_block(rd_device_t dev, struct rd_inode* in, size_t logical_idx, int allocate) {
    size_t per_block = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
    
    /* Direct blocks */
    if (logical_idx < RD_MAX_DIRECT) {
        if (in->blocks[logical_idx] == 0 && allocate) {
            int blk = rd_block_alloc(dev);
            if (blk < 0) {
                return blk;
            }
            in->blocks[logical_idx] = (uint32_t)blk;
        }
        return (int)in->blocks[logical_idx];
    }
    
    /* Single indirect blocks */
    size_t idx = logical_idx - RD_MAX_DIRECT;
    if (idx < per_block) {
        if (in->indirect == 0) {
            if (!allocate) {
                return 0;
            }
            int blk = rd_block_alloc(dev);
            if (blk < 0) {
                return blk;
            }
            in->indirect = (uint32_t)blk;
            rd_mark_dirty(dev, in->indirect);
        }
        uint32_t* table = (uint32_t*)rd_block_ptr(dev, in->indirect);
        if (!table) {
            return RD_ERR_IO;
        }
        if (table[idx] == 0 && allocate) {
            int blk = rd_block_alloc(dev);
            if (blk < 0) {
                return blk;
            }
            table[idx] = (uint32_t)blk;
            rd_mark_dirty(dev, in->indirect);
        }
        return (int)table[idx];
    }
    
    /* Double indirect blocks */
    idx -= per_block;
    if (idx >= per_block * per_block) {
        return RD_ERR_RANGE;
    }
    
    size_t di_idx = idx / per_block;
    size_t si_idx = idx % per_block;
    
    if (in->double_indirect == 0) {
        if (!allocate) {
            return 0;
        }
        int blk = rd_block_alloc(dev);
        if (blk < 0) {
            return blk;
        }
        in->double_indirect = (uint32_t)blk;
        rd_mark_dirty(dev, in->double_indirect);
    }
    
    uint32_t* di_table = (uint32_t*)rd_block_ptr(dev, in->double_indirect);
    if (!di_table) {
        return RD_ERR_IO;
    }
    
    if (di_table[di_idx] == 0) {
        if (!allocate) {
            return 0;
        }
        int blk = rd_block_alloc(dev);
        if (blk < 0) {
            return blk;
        }
        di_table[di_idx] = (uint32_t)blk;
        rd_mark_dirty(dev, in->double_indirect);
    }
    
    uint32_t* table = (uint32_t*)rd_block_ptr(dev, di_table[di_idx]);
    if (!table) {
        return RD_ERR_IO;
    }
    
    if (table[si_idx] == 0 && allocate) {
        int blk = rd_block_alloc(dev);
        if (blk < 0) {
            return blk;
        }
        table[si_idx] = (uint32_t)blk;
        rd_mark_dirty(dev, di_table[di_idx]);
    }
    
    return (int)table[si_idx];
}

static int rd_dir_add(rd_device_t dev, uint32_t dir_idx, uint32_t child_idx, const char* name, uint8_t ftype);
static int rd_dir_remove(rd_device_t dev, uint32_t dir_idx, const char* name, uint32_t* removed_inode);

static int rd_format(rd_device_t dev) {
    struct rd_superblock* sb = rd_sb(dev);
    memset(dev->data, 0, dev->size_bytes);

    uint32_t block_size = (uint32_t)dev->block_size;
    uint32_t block_count = (uint32_t)(dev->size_bytes / dev->block_size);
    if (block_count < 16) {
        return RD_ERR_NOSPC;
    }

    uint32_t bitmap_bytes = (block_count + 7u) / 8u;
    uint32_t bitmap_blocks = (bitmap_bytes + block_size - 1u) / block_size;

    uint32_t inode_count = block_count / 4u;
    if (inode_count < 16) {
        inode_count = 16;
    }
    uint32_t inode_bytes = inode_count * (uint32_t)sizeof(struct rd_inode);
    uint32_t inode_blocks = (inode_bytes + block_size - 1u) / block_size;

    uint32_t data_start = 1u + bitmap_blocks + inode_blocks;
    if (data_start >= block_count) {
        return RD_ERR_NOSPC;
    }

    sb->magic = RD_MAGIC;
    sb->version = RD_VERSION;
    sb->block_size = block_size;
    sb->block_count = block_count;
    sb->inode_count = inode_count;
    sb->bitmap_start = 1u;
    sb->inode_start = 1u + bitmap_blocks;
    sb->data_start = data_start;
    sb->root_inode = 0;
    sb->free_blocks = block_count - data_start;
    sb->free_inodes = inode_count - 1u;
    sb->free_block_head = 0;  /* Will be initialized below */
    sb->free_inode_head = 0;  /* Will be initialized below */

    for (uint32_t i = 0; i < data_start; ++i) {
        rd_bitmap_set(dev, i, 1);
    }
    
    /* Initialize free block list - chain all free blocks */
    sb->free_block_head = data_start;
    for (uint32_t i = data_start; i < block_count; ++i) {
        uint32_t* block_data = (uint32_t*)rd_block_ptr(dev, i);
        if (i + 1 < block_count) {
            block_data[0] = i + 1;  /* Next free block */
        } else {
            block_data[0] = 0;  /* End of list */
        }
    }
    
    /* Initialize free inode list - chain all free inodes except root (0) */
    if (inode_count > 1) {
        sb->free_inode_head = 1;
        struct rd_inode* base = rd_inode_base(dev);
        for (uint32_t i = 1; i < inode_count; ++i) {
            if (i + 1 < inode_count) {
                base[i].next_free = i + 1;
            } else {
                base[i].next_free = 0;  /* End of list */
            }
        }
    }

    struct rd_inode* root = rd_inode_get(dev, sb->root_inode);
    memset(root, 0, sizeof(*root));
    root->type = RD_FT_DIR;
    root->mode = 0755;
    root->links = 1;
    root->ctime = root->mtime = root->atime = rd_now_ns();

    int blk = rd_block_alloc(dev);
    if (blk < 0) {
        return blk;
    }
    root->blocks[0] = (uint32_t)blk;
    root->size = 0;
    int rc = rd_dir_add(dev, sb->root_inode, sb->root_inode, ".", RD_FT_DIR);
    if (rc != RD_OK) {
        return rc;
    }
    rc = rd_dir_add(dev, sb->root_inode, sb->root_inode, "..", RD_FT_DIR);
    if (rc != RD_OK) {
        return rc;
    }
    root->links = 2;
    
    /* Mark initial blocks as dirty */
    for (uint32_t i = 0; i < data_start; ++i) {
        rd_mark_dirty(dev, i);
    }
    
    return RD_OK;
}

static int rd_mount_existing(rd_device_t dev) {
    struct rd_superblock* sb = rd_sb(dev);
    if (sb->magic != RD_MAGIC || sb->version != RD_VERSION) {
        return RD_ERR_INVAL;
    }
    if (sb->block_size != dev->block_size) {
        return RD_ERR_INVAL;
    }
    return RD_OK;
}

static int rd_is_dir_empty(rd_device_t dev, uint32_t dir_idx) {
    struct rd_inode* dir = rd_inode_get(dev, dir_idx);
    if (!dir || dir->type != RD_FT_DIR) {
        return 0;
    }
    size_t off = 0;
    while (off < dir->size) {
        size_t blk_off = off / dev->block_size;
        int blk = rd_inode_get_block(dev, dir, blk_off, 0);
        if (blk <= 0) {
            /* Shouldn't happen for valid directory, but be safe */
            break;
        }
        unsigned char* blk_ptr = rd_block_ptr(dev, (uint32_t)blk);
        if (!blk_ptr) {
            break;
        }
        struct rd_dirent_disk* de = (struct rd_dirent_disk*)(blk_ptr + (off % dev->block_size));
        if (de->rec_len == 0) {
            break; /* Malformed directory */
        }
        if (de->inode != 0 && !(de->name_len == 1 && de->name[0] == '.') &&
            !(de->name_len == 2 && de->name[0] == '.' && de->name[1] == '.')) {
            return 0;
        }
        off += de->rec_len;
    }
    return 1;
}

static int rd_dir_add(rd_device_t dev, uint32_t dir_idx, uint32_t child_idx, const char* name, uint8_t ftype) {
    struct rd_inode* dir = rd_inode_get(dev, dir_idx);
    if (!dir || dir->type != RD_FT_DIR) {
        return RD_ERR_INVAL;
    }
    size_t name_len = strnlen(name, RD_MAX_NAME);
    if (name_len == 0 || name_len >= RD_MAX_NAME) {
        return RD_ERR_INVAL;
    }
    uint16_t needed = (uint16_t)((sizeof(struct rd_dirent_disk) + name_len + 3u) & ~3u);

    size_t off = 0;
    while (off < dir->size) {
        size_t blk_off = off / dev->block_size;
        int blk = rd_inode_get_block(dev, dir, blk_off, 0);
        if (blk <= 0) {
            break; /* Can't find space in existing entries */
        }
        unsigned char* blk_ptr = rd_block_ptr(dev, (uint32_t)blk);
        if (!blk_ptr) {
            return RD_ERR_IO;
        }
        size_t blk_inner = off % dev->block_size;
        struct rd_dirent_disk* de = (struct rd_dirent_disk*)(blk_ptr + blk_inner);
        if (de->rec_len == 0) {
            break; /* Malformed directory */
        }
        uint16_t actual = (uint16_t)((sizeof(struct rd_dirent_disk) + de->name_len + 3u) & ~3u);
        if (de->rec_len >= actual + needed && de->inode != 0) {
            uint16_t remaining = de->rec_len - actual;
            de->rec_len = actual;
            struct rd_dirent_disk* new_de = (struct rd_dirent_disk*)((unsigned char*)de + actual);
            new_de->inode = child_idx;
            new_de->rec_len = remaining;
            new_de->name_len = (uint8_t)name_len;
            new_de->file_type = ftype;
            memcpy(new_de->name, name, name_len);
            dir->mtime = dir->ctime = rd_now_ns();
            return RD_OK;
        }
        off += de->rec_len;
    }

    if (dir->size % dev->block_size == 0) {
        size_t block_idx = dir->size / dev->block_size;
        if (block_idx >= RD_MAX_DIRECT) {
            return RD_ERR_NOSPC;
        }
        int blk = rd_block_alloc(dev);
        if (blk < 0) {
            return blk;
        }
        dir->blocks[block_idx] = (uint32_t)blk;
        dir->size += dev->block_size;
    }

    size_t logical_blk_idx = dir->size > 0 ? (dir->size - 1) / dev->block_size : 0;
    int blk = rd_inode_get_block(dev, dir, logical_blk_idx, 0);
    if (blk <= 0) {
        return RD_ERR_IO;
    }
    size_t blk_off = dir->size > 0 ? (dir->size - dev->block_size) % dev->block_size : 0;
    if (dir->size == 0) {
        blk_off = 0;
    }
    unsigned char* blk_ptr = rd_block_ptr(dev, (uint32_t)blk);
    if (!blk_ptr) {
        return RD_ERR_IO;
    }
    struct rd_dirent_disk* de = (struct rd_dirent_disk*)(blk_ptr + blk_off);
    de->inode = child_idx;
    de->rec_len = (uint16_t)(dev->block_size - blk_off);
    de->name_len = (uint8_t)name_len;
    de->file_type = ftype;
    memcpy(de->name, name, name_len);
    dir->mtime = dir->ctime = rd_now_ns();
    return RD_OK;
}

static int rd_dir_find(rd_device_t dev, uint32_t dir_idx, const char* name, uint32_t* out_inode, uint8_t* out_ftype) {
    struct rd_inode* dir = rd_inode_get(dev, dir_idx);
    if (!dir || dir->type != RD_FT_DIR) {
        return RD_ERR_INVAL;
    }
    size_t name_len = strnlen(name, RD_MAX_NAME);
    if (name_len == 0 || name_len >= RD_MAX_NAME) {
        return RD_ERR_NOENT;
    }
    size_t off = 0;
    while (off < dir->size) {
        uint32_t blk_off = (uint32_t)(off / dev->block_size);
        uint32_t blk_idx = dir->blocks[blk_off];
        size_t blk_inner = off % dev->block_size;
        struct rd_dirent_disk* de = (struct rd_dirent_disk*)(rd_block_ptr(dev, blk_idx) + blk_inner);
        if (de->inode != 0 && de->name_len == name_len && memcmp(de->name, name, name_len) == 0) {
            if (out_inode) {
                *out_inode = de->inode;
            }
            if (out_ftype) {
                *out_ftype = de->file_type;
            }
            return RD_OK;
        }
        off += de->rec_len;
    }
    return RD_ERR_NOENT;
}

static int rd_dir_remove(rd_device_t dev, uint32_t dir_idx, const char* name, uint32_t* removed_inode) {
    struct rd_inode* dir = rd_inode_get(dev, dir_idx);
    if (!dir || dir->type != RD_FT_DIR) {
        return RD_ERR_INVAL;
    }
    size_t name_len = strnlen(name, RD_MAX_NAME);
    size_t off = 0;
    struct rd_dirent_disk* prev = NULL;
    while (off < dir->size) {
        size_t blk_off = off / dev->block_size;
        int blk = rd_inode_get_block(dev, dir, blk_off, 0);
        if (blk <= 0) {
            return RD_ERR_IO;
        }
        unsigned char* blk_ptr = rd_block_ptr(dev, (uint32_t)blk);
        if (!blk_ptr) {
            return RD_ERR_IO;
        }
        size_t blk_inner = off % dev->block_size;
        struct rd_dirent_disk* de = (struct rd_dirent_disk*)(blk_ptr + blk_inner);
        if (de->inode != 0 && de->name_len == name_len && memcmp(de->name, name, name_len) == 0) {
            if (removed_inode) {
                *removed_inode = de->inode;
            }
            if (prev) {
                prev->rec_len += de->rec_len;
            } else {
                de->inode = 0;
            }
            dir->mtime = dir->ctime = rd_now_ns();
            return RD_OK;
        }
        prev = de;
        off += de->rec_len;
    }
    return RD_ERR_NOENT;
}

static int rd_lookup(rd_device_t dev, const char* path, uint32_t* out_inode, uint32_t* parent_inode, char* leaf_buf, size_t leaf_buf_sz) {
    if (!path || path[0] != '/') {
        return RD_ERR_INVAL;
    }
    if (leaf_buf && leaf_buf_sz > 0) {
        leaf_buf[0] = '\0';
    }
    if (strcmp(path, "/") == 0) {
        if (out_inode) {
            *out_inode = rd_sb(dev)->root_inode;
        }
        if (parent_inode) {
            *parent_inode = rd_sb(dev)->root_inode;
        }
        return RD_OK;
    }

    char temp[256];
    size_t len = strnlen(path, sizeof(temp) - 1);
    if (len >= sizeof(temp)) {
        return RD_ERR_INVAL;
    }
    memcpy(temp, path, len + 1);

    uint32_t cur = rd_sb(dev)->root_inode;
    char last[RD_MAX_NAME] = {0};
    char* saveptr = NULL;
    char* token = strtok_r(temp + 1, "/", &saveptr);
    uint32_t parent = cur;
    while (token) {
        char* next = strtok_r(NULL, "/", &saveptr);
        uint32_t child = 0;
        uint8_t ftype = 0;
        int rc = rd_dir_find(dev, cur, token, &child, &ftype);
        if (rc != RD_OK) {
            if (next == NULL) {
                if (out_inode) {
                    *out_inode = UINT32_MAX;
                }
                if (parent_inode) {
                    *parent_inode = cur;
                }
                if (leaf_buf && leaf_buf_sz > 0) {
                    strncpy(leaf_buf, token, leaf_buf_sz - 1);
                    leaf_buf[leaf_buf_sz - 1] = '\0';
                }
                return RD_ERR_NOENT;
            }
            return rc;
        }
        parent = cur;
        cur = child;
        strncpy(last, token, RD_MAX_NAME - 1);
        token = next;
    }
    if (out_inode) {
        *out_inode = cur;
    }
    if (parent_inode) {
        *parent_inode = parent;
    }
    if (leaf_buf && leaf_buf_sz > 0) {
        strncpy(leaf_buf, last, leaf_buf_sz - 1);
        leaf_buf[leaf_buf_sz - 1] = '\0';
    }
    return RD_OK;
}

static int rd_grow_file(rd_device_t dev, struct rd_inode* in, size_t new_size) {
    if (new_size <= in->size) {
        return RD_OK;
    }
    size_t needed_blocks = (new_size + dev->block_size - 1) / dev->block_size;
    size_t have_blocks = (in->size + dev->block_size - 1) / dev->block_size;
    for (size_t i = have_blocks; i < needed_blocks; ++i) {
        int blk = rd_inode_get_block(dev, in, i, 1);
        if (blk < 0) {
            return blk;
        }
    }
    in->size = new_size;
    return RD_OK;
}

static ssize_t rd_rw_core(rd_device_t dev, rd_fd fd, const void* in_buf, void* out_buf, size_t len, size_t off, int write_mode) {
    struct rd_handle* h = NULL;
    if (fd >= 0 && (size_t)fd < dev->handle_capacity) {
        h = &dev->handles[fd];
    }
    if (!h || !h->used) {
        return RD_ERR_INVAL;
    }
    struct rd_inode* in = rd_inode_get(dev, h->inode_idx);
    if (!in) {
        return RD_ERR_INVAL;
    }
    if (in->type != RD_FT_FILE) {
        return RD_ERR_INVAL;
    }

    size_t end_pos = off + len;
    if (write_mode) {
        int rc = rd_grow_file(dev, in, end_pos);
        if (rc != RD_OK) {
            return rc;
        }
    } else {
        if (off >= in->size) {
            return 0;
        }
        if (end_pos > in->size) {
            len = in->size - off;
            end_pos = off + len;
        }
    }

    size_t remaining = len;
    size_t cursor = off;
    size_t copied = 0;
    while (remaining > 0) {
        size_t blk_idx = cursor / dev->block_size;
        int blk = rd_inode_get_block(dev, in, blk_idx, write_mode);
        if (blk <= 0) {
            if (!write_mode && blk == 0) {
                /* Sparse hole: treat as zeros. */
                size_t hole = dev->block_size - (cursor % dev->block_size);
                if (hole > remaining) {
                    hole = remaining;
                }
                memset((unsigned char*)out_buf + copied, 0, hole);
                remaining -= hole;
                copied += hole;
                cursor += hole;
                continue;
            }
            return blk;
        }
        size_t blk_off = cursor % dev->block_size;
        size_t take = dev->block_size - blk_off;
        if (take > remaining) {
            take = remaining;
        }
        unsigned char* blk_ptr = rd_block_ptr(dev, (uint32_t)blk);
        if (!blk_ptr) {
            return RD_ERR_IO;
        }
        if (write_mode) {
            memcpy(blk_ptr + blk_off, (const unsigned char*)in_buf + copied, take);
            rd_mark_dirty(dev, (uint32_t)blk);
        } else {
            memcpy((unsigned char*)out_buf + copied, blk_ptr + blk_off, take);
        }
        remaining -= take;
        copied += take;
        cursor += take;
    }
    if (write_mode) {
        in->mtime = in->ctime = rd_now_ns();
    } else {
        in->atime = rd_now_ns();
    }
    return (ssize_t)copied;
}

RD_API rd_device_t rd_create(size_t size_bytes,
                             size_t block_size,
                             const char* backing_path,
                             unsigned flags) {
    if (size_bytes == 0 || block_size == 0 || (block_size & (block_size - 1u)) != 0) {
        errno = EINVAL;
        return NULL;
    }
    if (size_bytes % block_size != 0) {
        errno = EINVAL;
        return NULL;
    }

    rd_device_t dev = (rd_device_t)calloc(1, sizeof(*dev));
    if (!dev) {
        return NULL;
    }

    dev->size_bytes = size_bytes;
    dev->block_size = block_size;
    
    /* Initialize locks */
    if (pthread_rwlock_init(&dev->fs_lock, NULL) != 0) {
        free(dev);
        errno = ENOMEM;
        return NULL;
    }
    if (pthread_mutex_init(&dev->handle_lock, NULL) != 0) {
        pthread_rwlock_destroy(&dev->fs_lock);
        free(dev);
        errno = ENOMEM;
        return NULL;
    }
    
    /* Initialize dynamic handle table */
    dev->handle_capacity = RD_MAX_HANDLES;
    dev->handles = (struct rd_handle*)calloc(dev->handle_capacity, sizeof(struct rd_handle));
    if (!dev->handles) {
        pthread_mutex_destroy(&dev->handle_lock);
        pthread_rwlock_destroy(&dev->fs_lock);
        free(dev);
        errno = ENOMEM;
        return NULL;
    }
    if (backing_path) {
        size_t len = strlen(backing_path) + 1;
        dev->backing_path = (char*)malloc(len);
        if (!dev->backing_path) {
            free(dev);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(dev->backing_path, backing_path, len);
        const char* mode = (flags & RD_BACKING_TRUNC) ? "w+b" : "r+b";
        dev->backing_file = fopen(backing_path, mode);
        if (!dev->backing_file && !(flags & RD_BACKING_TRUNC)) {
            dev->backing_file = fopen(backing_path, "w+b");
        }
        if (!dev->backing_file) {
            free(dev->backing_path);
            free(dev);
            return NULL;
        }
        dev->backing_present = 1;
        if (fseek(dev->backing_file, 0, SEEK_END) != 0) {
            /* ignore */
        }
        long fsz = ftell(dev->backing_file);
        if (fsz < 0 || (size_t)fsz < size_bytes) {
            /* Ensure file is large enough */
            if (fseek(dev->backing_file, 0, SEEK_SET) == 0) {
                /* Write in chunks to avoid overflow with large files */
                size_t remaining = size_bytes;
                unsigned char zero_buf[4096] = {0};
                while (remaining > 0) {
                    size_t chunk = remaining > sizeof(zero_buf) ? sizeof(zero_buf) : remaining;
                    if (fwrite(zero_buf, 1, chunk, dev->backing_file) != chunk) {
                        break;
                    }
                    remaining -= chunk;
                }
                fflush(dev->backing_file);
            }
        }
        rewind(dev->backing_file);
    }

    dev->data = (unsigned char*)rd_alloc_aligned(size_bytes, block_size);
    if (!dev->data) {
        if (dev->backing_file) {
            fclose(dev->backing_file);
        }
        free(dev->backing_path);
        free(dev->handles);
        pthread_mutex_destroy(&dev->handle_lock);
        pthread_rwlock_destroy(&dev->fs_lock);
        free(dev);
        errno = ENOMEM;
        return NULL;
    }
    memset(dev->data, 0, size_bytes);
    
    /* Allocate dirty bitmap for incremental flushing */
    if (dev->backing_file) {
        size_t block_count = size_bytes / block_size;
        size_t bitmap_bytes = (block_count + 7) / 8;
        dev->dirty_bitmap = (unsigned char*)calloc(1, bitmap_bytes);
        if (!dev->dirty_bitmap) {
            rd_free_aligned(dev->data);
            if (dev->backing_file) {
                fclose(dev->backing_file);
            }
            free(dev->backing_path);
            free(dev->handles);
            pthread_mutex_destroy(&dev->handle_lock);
            pthread_rwlock_destroy(&dev->fs_lock);
            free(dev);
            errno = ENOMEM;
            return NULL;
        }
    }

    if (dev->backing_file && !(flags & RD_BACKING_TRUNC)) {
        size_t read = fread(dev->data, 1, size_bytes, dev->backing_file);
        (void)read;
        rewind(dev->backing_file);
    }

    return dev;
}

RD_API int rd_mount(rd_device_t dev) {
    if (!dev) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    struct rd_superblock* sb = rd_sb(dev);
    int rc;
    if (sb->magic != RD_MAGIC) {
        rc = rd_format(dev);
    } else {
        rc = rd_mount_existing(dev);
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    return rc;
}

RD_API int rd_unmount(rd_device_t dev) {
    if (!dev) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    int rc = rd_block_flush(dev);
    pthread_rwlock_unlock(&dev->fs_lock);
    if (rc != RD_OK) {
        return rc;
    }
    return RD_OK;
}

RD_API void rd_destroy(rd_device_t dev) {
    if (!dev) {
        return;
    }
    if (dev->backing_file) {
        fclose(dev->backing_file);
    }
    rd_free_aligned(dev->data);
    free(dev->backing_path);
    free(dev->handles);
    free(dev->dirty_bitmap);
    pthread_mutex_destroy(&dev->handle_lock);
    pthread_rwlock_destroy(&dev->fs_lock);
    free(dev);
}

RD_API ssize_t rd_block_read(rd_device_t dev,
                             size_t block_idx,
                             void* buf,
                             size_t block_count) {
    if (!dev || !buf) {
        return RD_ERR_INVAL;
    }
    size_t offset = block_idx * dev->block_size;
    size_t len = block_count * dev->block_size;
    if (offset > dev->size_bytes || len > dev->size_bytes || offset + len > dev->size_bytes) {
        return RD_ERR_RANGE;
    }
    pthread_rwlock_rdlock(&dev->fs_lock);
    memcpy(buf, dev->data + offset, len);
    pthread_rwlock_unlock(&dev->fs_lock);
    return (ssize_t)block_count;
}

RD_API ssize_t rd_block_write(rd_device_t dev,
                              size_t block_idx,
                              const void* buf,
                              size_t block_count) {
    if (!dev || !buf) {
        return RD_ERR_INVAL;
    }
    size_t offset = block_idx * dev->block_size;
    size_t len = block_count * dev->block_size;
    if (offset > dev->size_bytes || len > dev->size_bytes || offset + len > dev->size_bytes) {
        return RD_ERR_RANGE;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    memcpy(dev->data + offset, buf, len);
    /* Mark written blocks as dirty */
    for (size_t i = 0; i < block_count; ++i) {
        rd_mark_dirty(dev, (uint32_t)(block_idx + i));
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    return (ssize_t)block_count;
}

RD_API int rd_block_flush(rd_device_t dev) {
    if (!dev) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_rdlock(&dev->fs_lock);
    if (dev->backing_file) {
        struct rd_superblock* sb = rd_sb(dev);
        if (dev->dirty_bitmap) {
            /* Incremental flush: only write dirty blocks */
            for (uint32_t i = 0; i < sb->block_count; ++i) {
                if (rd_is_dirty(dev, i)) {
                    size_t offset = (size_t)i * dev->block_size;
                    if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
                        return RD_ERR_IO;
                    }
                    size_t written = fwrite(dev->data + offset, 1, dev->block_size, dev->backing_file);
                    if (written < dev->block_size) {
                        return RD_ERR_IO;
                    }
                    rd_clear_dirty(dev, i);
                }
            }
        } else {
            /* Full flush if no dirty tracking */
            rewind(dev->backing_file);
            size_t written = fwrite(dev->data, 1, dev->size_bytes, dev->backing_file);
            if (written < dev->size_bytes) {
                return RD_ERR_IO;
            }
        }
        fflush(dev->backing_file);
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

static int rd_handle_alloc(rd_device_t dev) {
    pthread_mutex_lock(&dev->handle_lock);
    
    /* First, try to find an unused handle */
    for (size_t i = 0; i < dev->handle_capacity; ++i) {
        if (!dev->handles[i].used) {
            dev->handles[i].used = 1;
            dev->handles[i].offset = 0;
            pthread_mutex_unlock(&dev->handle_lock);
            return (int)i;
        }
    }
    
    /* All handles in use, try to grow the table */
    size_t new_capacity = dev->handle_capacity * 2;
    if (new_capacity > 1024) {
        /* Cap at 1024 handles to prevent excessive growth */
        pthread_mutex_unlock(&dev->handle_lock);
        return RD_ERR_NOSPC;
    }
    
    struct rd_handle* new_handles = (struct rd_handle*)realloc(
        dev->handles, new_capacity * sizeof(struct rd_handle));
    if (!new_handles) {
        pthread_mutex_unlock(&dev->handle_lock);
        return RD_ERR_NOMEM;
    }
    
    /* Initialize new handles */
    memset(new_handles + dev->handle_capacity, 0, 
           (new_capacity - dev->handle_capacity) * sizeof(struct rd_handle));
    
    dev->handles = new_handles;
    size_t idx = dev->handle_capacity;
    dev->handle_capacity = new_capacity;
    
    dev->handles[idx].used = 1;
    dev->handles[idx].offset = 0;
    pthread_mutex_unlock(&dev->handle_lock);
    return (int)idx;
}

static struct rd_handle* rd_handle_get(rd_device_t dev, rd_fd fd) {
    pthread_mutex_lock(&dev->handle_lock);
    if (fd < 0 || (size_t)fd >= dev->handle_capacity) {
        pthread_mutex_unlock(&dev->handle_lock);
        return NULL;
    }
    if (!dev->handles[fd].used) {
        pthread_mutex_unlock(&dev->handle_lock);
        return NULL;
    }
    /* Note: We keep the lock held and return pointer - caller must call rd_handle_release */
    return &dev->handles[fd];
}

static void rd_handle_release(rd_device_t dev) {
    pthread_mutex_unlock(&dev->handle_lock);
}

RD_API rd_fd rd_open(rd_device_t dev, const char* path, unsigned flags, unsigned mode) {
    if (!dev || !path) {
        return RD_ERR_INVAL;
    }
    
    pthread_rwlock_wrlock(&dev->fs_lock);
    
    uint32_t inode = 0;
    uint32_t parent = 0;
    char leaf[RD_MAX_NAME];
    int rc = rd_lookup(dev, path, &inode, &parent, leaf, sizeof(leaf));
    if (rc == RD_ERR_NOENT) {
        if (!(flags & RD_O_CREATE)) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_NOENT;
        }
        if (leaf[0] == '\0') {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_INVAL;
        }
        int new_inode = rd_inode_alloc(dev);
        if (new_inode < 0) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return new_inode;
        }
        struct rd_inode* in = rd_inode_get(dev, (uint32_t)new_inode);
        memset(in, 0, sizeof(*in));
        in->type = RD_FT_FILE;
        in->mode = (uint16_t)mode;
        in->links = 1;
        in->ctime = in->mtime = in->atime = rd_now_ns();
        rc = rd_dir_add(dev, parent, (uint32_t)new_inode, leaf, RD_FT_FILE);
        if (rc != RD_OK) {
            rd_inode_free(dev, (uint32_t)new_inode);
            pthread_rwlock_unlock(&dev->fs_lock);
            return rc;
        }
        inode = (uint32_t)new_inode;
    } else if (rc == RD_OK && (flags & RD_O_EXCL) && (flags & RD_O_CREATE)) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_EXIST;
    } else if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }

    struct rd_inode* in = rd_inode_get(dev, inode);
    if (!in) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_INVAL;
    }
    if (in->type == RD_FT_DIR && (flags & (RD_O_WRONLY | RD_O_RDWR))) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_PERM;
    }
    if ((flags & RD_O_TRUNC) && in->type == RD_FT_FILE) {
        /* Free double indirect blocks first */
        if (in->double_indirect) {
            uint32_t* di_table = (uint32_t*)rd_block_ptr(dev, in->double_indirect);
            size_t di_limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
            for (size_t i = 0; i < di_limit; ++i) {
                if (di_table[i]) {
                    uint32_t* table = (uint32_t*)rd_block_ptr(dev, di_table[i]);
                    size_t limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
                    for (size_t j = 0; j < limit; ++j) {
                        if (table[j]) {
                            rd_block_free(dev, table[j]);
                        }
                    }
                    rd_block_free(dev, di_table[i]);
                }
            }
            rd_block_free(dev, in->double_indirect);
            in->double_indirect = 0;
        }
        /* Free indirect blocks */
        if (in->indirect) {
            uint32_t* table = (uint32_t*)rd_block_ptr(dev, in->indirect);
            size_t limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
            for (size_t i = 0; i < limit; ++i) {
                if (table[i]) {
                    rd_block_free(dev, table[i]);
                }
            }
            rd_block_free(dev, in->indirect);
            in->indirect = 0;
        }
        /* Free direct blocks */
        for (size_t i = 0; i < RD_MAX_DIRECT; ++i) {
            if (in->blocks[i]) {
                rd_block_free(dev, in->blocks[i]);
                in->blocks[i] = 0;
            }
        }
        in->size = 0;
        in->mtime = in->ctime = rd_now_ns();
    }

    int hidx = rd_handle_alloc(dev);
    if (hidx < 0) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return hidx;
    }
    dev->handles[hidx].inode_idx = inode;
    dev->handles[hidx].flags = flags;
    dev->handles[hidx].offset = (flags & RD_O_APPEND) ? in->size : 0;
    pthread_rwlock_unlock(&dev->fs_lock);
    return hidx;
}

RD_API ssize_t rd_read(rd_device_t dev, rd_fd fd, void* buf, size_t len) {
    if (!dev || !buf) {
        return RD_ERR_INVAL;
    }
    struct rd_handle* h = rd_handle_get(dev, fd);
    if (!h) {
        return RD_ERR_INVAL;
    }
    size_t offset = h->offset;
    rd_handle_release(dev);
    
    pthread_rwlock_rdlock(&dev->fs_lock);
    ssize_t r = rd_rw_core(dev, fd, NULL, buf, len, offset, 0);
    pthread_rwlock_unlock(&dev->fs_lock);
    
    if (r >= 0) {
        pthread_mutex_lock(&dev->handle_lock);
        if (fd >= 0 && (size_t)fd < dev->handle_capacity && dev->handles[fd].used) {
            dev->handles[fd].offset += (size_t)r;
        }
        pthread_mutex_unlock(&dev->handle_lock);
    }
    return r;
}

RD_API ssize_t rd_write(rd_device_t dev, rd_fd fd, const void* buf, size_t len) {
    if (!dev || !buf) {
        return RD_ERR_INVAL;
    }
    struct rd_handle* h = rd_handle_get(dev, fd);
    if (!h) {
        return RD_ERR_INVAL;
    }
    size_t offset = h->offset;
    rd_handle_release(dev);
    
    pthread_rwlock_wrlock(&dev->fs_lock);
    ssize_t r = rd_rw_core(dev, fd, buf, NULL, len, offset, 1);
    pthread_rwlock_unlock(&dev->fs_lock);
    
    if (r >= 0) {
        pthread_mutex_lock(&dev->handle_lock);
        if (fd >= 0 && (size_t)fd < dev->handle_capacity && dev->handles[fd].used) {
            dev->handles[fd].offset += (size_t)r;
        }
        pthread_mutex_unlock(&dev->handle_lock);
    }
    return r;
}

RD_API ssize_t rd_pread(rd_device_t dev, rd_fd fd, void* buf, size_t len, size_t off) {
    if (!dev || !buf) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_rdlock(&dev->fs_lock);
    ssize_t r = rd_rw_core(dev, fd, NULL, buf, len, off, 0);
    pthread_rwlock_unlock(&dev->fs_lock);
    return r;
}

RD_API ssize_t rd_pwrite(rd_device_t dev, rd_fd fd, const void* buf, size_t len, size_t off) {
    if (!dev || !buf) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    ssize_t r = rd_rw_core(dev, fd, buf, NULL, len, off, 1);
    pthread_rwlock_unlock(&dev->fs_lock);
    return r;
}

RD_API int rd_seek(rd_device_t dev, rd_fd fd, long long off, int whence) {
    struct rd_handle* h = rd_handle_get(dev, fd);
    if (!h) {
        return RD_ERR_INVAL;
    }
    
    pthread_rwlock_rdlock(&dev->fs_lock);
    struct rd_inode* in = rd_inode_get(dev, h->inode_idx);
    if (!in) {
        pthread_rwlock_unlock(&dev->fs_lock);
        rd_handle_release(dev);
        return RD_ERR_INVAL;
    }
    
    long long new_offset;
    if (whence == 0 || whence == SEEK_SET) {
        new_offset = off;
    } else if (whence == 1 || whence == SEEK_CUR) {
        new_offset = (long long)h->offset + off;
    } else if (whence == 2 || whence == SEEK_END) {
        new_offset = (long long)in->size + off;
    } else {
        pthread_rwlock_unlock(&dev->fs_lock);
        rd_handle_release(dev);
        return RD_ERR_INVAL;
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    
    if (new_offset < 0) {
        rd_handle_release(dev);
        return RD_ERR_INVAL;
    }
    h->offset = (size_t)new_offset;
    rd_handle_release(dev);
    return RD_OK;
}

RD_API int rd_close(rd_device_t dev, rd_fd fd) {
    struct rd_handle* h = rd_handle_get(dev, fd);
    if (!h) {
        return RD_ERR_INVAL;
    }
    memset(h, 0, sizeof(*h));
    rd_handle_release(dev);
    return RD_OK;
}

RD_API int rd_fstat(rd_device_t dev, rd_fd fd, rd_stat_info* st) {
    struct rd_handle* h = rd_handle_get(dev, fd);
    if (!h || !st) {
        if (h) rd_handle_release(dev);
        return RD_ERR_INVAL;
    }
    uint32_t inode_idx = h->inode_idx;
    rd_handle_release(dev);
    
    pthread_rwlock_rdlock(&dev->fs_lock);
    struct rd_inode* in = rd_inode_get(dev, inode_idx);
    if (!in) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_INVAL;
    }
    st->size_bytes = in->size;
    st->mode = in->mode;
    st->type = in->type;
    st->atime_ns = in->atime;
    st->mtime_ns = in->mtime;
    st->ctime_ns = in->ctime;
    st->link_count = in->links;
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

RD_API int rd_stat(rd_device_t dev, const char* path, rd_stat_info* st) {
    if (!dev || !path || !st) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_rdlock(&dev->fs_lock);
    uint32_t inode = 0;
    int rc = rd_lookup(dev, path, &inode, NULL, NULL, 0);
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    struct rd_inode* in = rd_inode_get(dev, inode);
    if (!in) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_INVAL;
    }
    st->size_bytes = in->size;
    st->mode = in->mode;
    st->type = in->type;
    st->atime_ns = in->atime;
    st->mtime_ns = in->mtime;
    st->ctime_ns = in->ctime;
    st->link_count = in->links;
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

RD_API int rd_unlink(rd_device_t dev, const char* path) {
    if (!dev || !path) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    uint32_t inode = 0;
    uint32_t parent = 0;
    char leaf[RD_MAX_NAME];
    int rc = rd_lookup(dev, path, &inode, &parent, leaf, sizeof(leaf));
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    if (leaf[0] == '\0') {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_PERM;
    }
    struct rd_inode* in = rd_inode_get(dev, inode);
    if (!in || in->type == RD_FT_DIR) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_PERM;
    }
    uint32_t removed = 0;
    rc = rd_dir_remove(dev, parent, leaf, &removed);
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    if (removed != inode) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_IO;
    }
    if (in->links > 0) {
        in->links--;
    }
    if (in->links == 0) {
        rd_inode_free(dev, inode);
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

RD_API int rd_mkdir(rd_device_t dev, const char* path) {
    if (!dev || !path) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    uint32_t inode = 0;
    uint32_t parent = 0;
    char leaf[RD_MAX_NAME];
    int rc = rd_lookup(dev, path, &inode, &parent, leaf, sizeof(leaf));
    if (rc == RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_EXIST;
    }
    if (rc != RD_ERR_NOENT || leaf[0] == '\0') {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    int new_inode = rd_inode_alloc(dev);
    if (new_inode < 0) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return new_inode;
    }
    struct rd_inode* dir = rd_inode_get(dev, (uint32_t)new_inode);
    memset(dir, 0, sizeof(*dir));
    dir->type = RD_FT_DIR;
    dir->mode = 0755;
    dir->links = 2;
    dir->ctime = dir->mtime = dir->atime = rd_now_ns();
    int blk = rd_block_alloc(dev);
    if (blk < 0) {
        rd_inode_free(dev, (uint32_t)new_inode);
        pthread_rwlock_unlock(&dev->fs_lock);
        return blk;
    }
    dir->blocks[0] = (uint32_t)blk;
    dir->size = 0;
    rc = rd_dir_add(dev, (uint32_t)new_inode, (uint32_t)new_inode, ".", RD_FT_DIR);
    if (rc != RD_OK) {
        rd_inode_free(dev, (uint32_t)new_inode);
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    rc = rd_dir_add(dev, (uint32_t)new_inode, parent, "..", RD_FT_DIR);
    if (rc != RD_OK) {
        /* Clean up the "." entry by clearing the directory */
        dir->size = 0;
        rd_inode_free(dev, (uint32_t)new_inode);
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    rc = rd_dir_add(dev, parent, (uint32_t)new_inode, leaf, RD_FT_DIR);
    if (rc != RD_OK) {
        /* Directory entries are cleaned by rd_inode_free */
        rd_inode_free(dev, (uint32_t)new_inode);
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

RD_API int rd_rmdir(rd_device_t dev, const char* path) {
    if (!dev || !path) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_wrlock(&dev->fs_lock);
    uint32_t inode = 0;
    uint32_t parent = 0;
    char leaf[RD_MAX_NAME];
    int rc = rd_lookup(dev, path, &inode, &parent, leaf, sizeof(leaf));
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    if (leaf[0] == '\0') {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_PERM;
    }
    struct rd_inode* dir = rd_inode_get(dev, inode);
    if (!dir || dir->type != RD_FT_DIR) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_PERM;
    }
    if (!rd_is_dir_empty(dev, inode)) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_PERM;
    }
    uint32_t removed = 0;
    rc = rd_dir_remove(dev, parent, leaf, &removed);
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    if (removed != inode) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_IO;
    }
    rd_inode_free(dev, inode);
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

RD_API int rd_readdir(rd_device_t dev, const char* path, rd_dirent_cb cb, void* user) {
    if (!dev || !path || !cb) {
        return RD_ERR_INVAL;
    }
    pthread_rwlock_rdlock(&dev->fs_lock);
    uint32_t inode = 0;
    int rc = rd_lookup(dev, path, &inode, NULL, NULL, 0);
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    struct rd_inode* dir = rd_inode_get(dev, inode);
    if (!dir || dir->type != RD_FT_DIR) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_INVAL;
    }
    size_t off = 0;
    while (off < dir->size) {
        uint32_t blk_off = (uint32_t)(off / dev->block_size);
        uint32_t blk_idx = dir->blocks[blk_off];
        size_t blk_inner = off % dev->block_size;
        struct rd_dirent_disk* de = (struct rd_dirent_disk*)(rd_block_ptr(dev, blk_idx) + blk_inner);
        if (de->inode != 0) {
            rd_stat_info st;
            struct rd_inode* in = rd_inode_get(dev, de->inode);
            if (in) {
                st.size_bytes = in->size;
                st.mode = in->mode;
                st.type = in->type;
                st.atime_ns = in->atime;
                st.mtime_ns = in->mtime;
                st.ctime_ns = in->ctime;
                st.link_count = in->links;
            } else {
                memset(&st, 0, sizeof(st));
            }
            char name_buf[RD_MAX_NAME + 1];
            size_t nlen = de->name_len < RD_MAX_NAME ? de->name_len : RD_MAX_NAME;
            memcpy(name_buf, de->name, nlen);
            name_buf[nlen] = '\0';
            int cbr = cb(name_buf, &st, user);
            if (cbr != 0) {
                break;
            }
        }
        off += de->rec_len;
    }
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}
RD_API int rd_rename(rd_device_t dev, const char* old_path, const char* new_path) {
    if (!dev || !old_path || !new_path) {
        return RD_ERR_INVAL;
    }
    
    pthread_rwlock_wrlock(&dev->fs_lock);
    
    /* Look up old path */
    uint32_t old_inode = 0;
    uint32_t old_parent = 0;
    char old_leaf[RD_MAX_NAME];
    int rc = rd_lookup(dev, old_path, &old_inode, &old_parent, old_leaf, sizeof(old_leaf));
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    
    struct rd_inode* old_in = rd_inode_get(dev, old_inode);
    if (!old_in) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_INVAL;
    }
    
    /* Look up new path */
    uint32_t new_inode = 0;
    uint32_t new_parent = 0;
    char new_leaf[RD_MAX_NAME];
    rc = rd_lookup(dev, new_path, &new_inode, &new_parent, new_leaf, sizeof(new_leaf));
    
    if (rc == RD_OK) {
        /* Destination exists - need to replace it */
        struct rd_inode* new_in = rd_inode_get(dev, new_inode);
        if (!new_in) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
        
        /* Cannot rename over a non-empty directory */
        if (new_in->type == RD_FT_DIR) {
            if (!rd_is_dir_empty(dev, new_inode)) {
                pthread_rwlock_unlock(&dev->fs_lock);
                return RD_ERR_PERM;
            }
        }
        
        /* Cannot rename directory over file or vice versa */
        if (old_in->type != new_in->type) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_PERM;
        }
        
        /* Remove the target */
        uint32_t removed = 0;
        rc = rd_dir_remove(dev, new_parent, new_leaf, &removed);
        if (rc != RD_OK) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return rc;
        }
        
        /* Free the target inode if it's not referenced */
        if (new_in->links > 0) {
            new_in->links--;
        }
        if (new_in->links == 0) {
            rd_inode_free(dev, new_inode);
        }
    } else if (rc != RD_ERR_NOENT) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    
    /* If new_leaf is empty, target parent doesn't exist */
    if (new_leaf[0] == '\0') {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_NOENT;
    }
    
    /* Check for directory cycles - cannot rename dir into its own subtree */
    if (old_in->type == RD_FT_DIR && new_parent != old_parent) {
        /* Simple check: new_parent cannot be old_inode or a child of old_inode */
        uint32_t check = new_parent;
        struct rd_superblock* sb = rd_sb(dev);
        while (check != sb->root_inode) {
            if (check == old_inode) {
                pthread_rwlock_unlock(&dev->fs_lock);
                return RD_ERR_INVAL;  /* Would create cycle */
            }
            /* Get parent of check by looking up ".." */
            uint32_t parent_ino = 0;
            rc = rd_dir_find(dev, check, "..", &parent_ino, NULL);
            if (rc != RD_OK || parent_ino == check) {
                break;  /* Reached root or error */
            }
            check = parent_ino;
        }
    }
    
    /* Remove from old parent */
    uint32_t removed = 0;
    rc = rd_dir_remove(dev, old_parent, old_leaf, &removed);
    if (rc != RD_OK) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    
    /* Add to new parent */
    rc = rd_dir_add(dev, new_parent, old_inode, new_leaf, old_in->type);
    if (rc != RD_OK) {
        /* Try to restore old entry - if this fails, we've lost the file */
        rd_dir_add(dev, old_parent, old_inode, old_leaf, old_in->type);
        pthread_rwlock_unlock(&dev->fs_lock);
        return rc;
    }
    
    /* Update parent links if moving directory between different parents */
    if (old_in->type == RD_FT_DIR && old_parent != new_parent) {
        struct rd_inode* old_parent_in = rd_inode_get(dev, old_parent);
        if (old_parent_in && old_parent_in->links > 0) {
            old_parent_in->links--;
        }
        
        struct rd_inode* new_parent_in = rd_inode_get(dev, new_parent);
        if (new_parent_in) {
            new_parent_in->links++;
        }
        
        /* Update ".." in moved directory to point to new parent */
        uint32_t dotdot_ino = 0;
        rc = rd_dir_find(dev, old_inode, "..", &dotdot_ino, NULL);
        if (rc == RD_OK) {
            uint32_t removed_dotdot = 0;
            rd_dir_remove(dev, old_inode, "..", &removed_dotdot);
            rd_dir_add(dev, old_inode, new_parent, "..", RD_FT_DIR);
        }
    }
    
    old_in->ctime = rd_now_ns();
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}

RD_API int rd_fsync(rd_device_t dev, rd_fd fd) {
    if (!dev) {
        return RD_ERR_INVAL;
    }
    
    struct rd_handle* h = rd_handle_get(dev, fd);
    if (!h) {
        return RD_ERR_INVAL;
    }
    
    uint32_t inode_idx = h->inode_idx;
    rd_handle_release(dev);
    
    if (!dev->backing_file) {
        return RD_OK;  /* No backing file, nothing to sync */
    }
    
    pthread_rwlock_rdlock(&dev->fs_lock);
    
    struct rd_inode* in = rd_inode_get(dev, inode_idx);
    if (!in) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_INVAL;
    }
    
    struct rd_superblock* sb = rd_sb(dev);
    
    /* Flush superblock */
    if (fseek(dev->backing_file, 0, SEEK_SET) != 0) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_IO;
    }
    if (fwrite(dev->data, dev->block_size, 1, dev->backing_file) != 1) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_IO;
    }
    
    /* Flush inode table blocks containing this inode */
    uint32_t inode_block = inode_idx / (dev->block_size / sizeof(struct rd_inode));
    uint32_t inode_block_abs = sb->inode_start + inode_block;
    size_t offset = (size_t)inode_block_abs * dev->block_size;
    if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_IO;
    }
    if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
        pthread_rwlock_unlock(&dev->fs_lock);
        return RD_ERR_IO;
    }
    
    /* Flush bitmap blocks */
    for (uint32_t i = 0; i < (sb->block_count + 7) / 8 / dev->block_size + 1; ++i) {
        uint32_t bm_block = sb->bitmap_start + i;
        if (bm_block >= sb->block_count) break;
        offset = (size_t)bm_block * dev->block_size;
        if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
        if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
    }
    
    /* Flush all data blocks belonging to this file */
    /* Direct blocks */
    for (size_t i = 0; i < RD_MAX_DIRECT; ++i) {
        if (in->blocks[i]) {
            offset = (size_t)in->blocks[i] * dev->block_size;
            if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
                pthread_rwlock_unlock(&dev->fs_lock);
                return RD_ERR_IO;
            }
            if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
                pthread_rwlock_unlock(&dev->fs_lock);
                return RD_ERR_IO;
            }
        }
    }
    
    /* Indirect block */
    if (in->indirect) {
        offset = (size_t)in->indirect * dev->block_size;
        if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
        if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
        
        /* Flush indirect data blocks */
        uint32_t* table = (uint32_t*)rd_block_ptr(dev, in->indirect);
        size_t limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
        for (size_t i = 0; i < limit; ++i) {
            if (table[i]) {
                offset = (size_t)table[i] * dev->block_size;
                if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
                    pthread_rwlock_unlock(&dev->fs_lock);
                    return RD_ERR_IO;
                }
                if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
                    pthread_rwlock_unlock(&dev->fs_lock);
                    return RD_ERR_IO;
                }
            }
        }
    }
    
    /* Double indirect block */
    if (in->double_indirect) {
        offset = (size_t)in->double_indirect * dev->block_size;
        if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
        if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
            pthread_rwlock_unlock(&dev->fs_lock);
            return RD_ERR_IO;
        }
        
        /* Flush double indirect tables and data blocks */
        uint32_t* di_table = (uint32_t*)rd_block_ptr(dev, in->double_indirect);
        size_t di_limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
        for (size_t i = 0; i < di_limit; ++i) {
            if (di_table[i]) {
                /* Flush indirect table */
                offset = (size_t)di_table[i] * dev->block_size;
                if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
                    pthread_rwlock_unlock(&dev->fs_lock);
                    return RD_ERR_IO;
                }
                if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
                    pthread_rwlock_unlock(&dev->fs_lock);
                    return RD_ERR_IO;
                }
                
                /* Flush data blocks */
                uint32_t* table = (uint32_t*)rd_block_ptr(dev, di_table[i]);
                size_t limit = RD_MAX_INDIRECT_ENTRIES(dev->block_size);
                for (size_t j = 0; j < limit; ++j) {
                    if (table[j]) {
                        offset = (size_t)table[j] * dev->block_size;
                        if (fseek(dev->backing_file, (long)offset, SEEK_SET) != 0) {
                            pthread_rwlock_unlock(&dev->fs_lock);
                            return RD_ERR_IO;
                        }
                        if (fwrite(dev->data + offset, dev->block_size, 1, dev->backing_file) != 1) {
                            pthread_rwlock_unlock(&dev->fs_lock);
                            return RD_ERR_IO;
                        }
                    }
                }
            }
        }
    }
    
    fflush(dev->backing_file);
    pthread_rwlock_unlock(&dev->fs_lock);
    return RD_OK;
}
