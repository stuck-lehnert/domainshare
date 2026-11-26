/* Debian Bookworm Samba 4.17.12 bridge for two already-open descriptors.
 * The Samba library owns record serialization and locking.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef SAMBA_PRIVATE_DIR
#error Define SAMBA_PRIVATE_DIR to the Bookworm Samba private library directory.
#endif

#define BOOKWORM_ABI "SAMBA_4.17.12_DEBIAN_SAMBA4"
#define TARGET_FD 3
#define DATABASE_FD 4
#define MAX_BLOB (84 + UINT16_MAX)

struct file_id {
    uint64_t device;
    uint64_t inode;
    uint64_t extid;
};

struct db_context;
struct loadparm_context;

static int fail(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, errno ? strerror(errno) : "failed");
    return 1;
}

static int has_managed_header(const unsigned char *blob, size_t size)
{
    static const unsigned char header[] = {
        1, 0, 1, 0, 0, 0, 2, 0, 1, 0, 4, 0x90,
        28, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 84, 0, 0, 0,
    };
    if (size < 92 || size > MAX_BLOB || memcmp(blob, header, sizeof(header)) != 0) {
        return 0;
    }

    size_t acl_size = blob[86] | ((size_t)blob[87] << 8);
    return blob[84] == 4 && blob[85] == 0 && acl_size == size - 84;
}

static int persist(const struct file_id *id, const unsigned char *blob, size_t size)
{
    void *samba = dlopen(SAMBA_PRIVATE_DIR "/libxattr-tdb-samba4.so.0",
                         RTLD_NOW | RTLD_LOCAL);
    if (!samba) {
        fprintf(stderr, "load Bookworm Samba ACL ABI: %s\n", dlerror());
        return 1;
    }

    struct db_context *(*db_open)(void *, const char *, int, int, int, mode_t,
                                  int, uint64_t) = dlvsym(samba, "db_open_tdb", BOOKWORM_ABI);
    int (*setattr)(struct db_context *, const struct file_id *, const char *,
                   const void *, size_t, int) = dlvsym(samba, "xattr_tdb_setattr", BOOKWORM_ABI);
    int (*release)(void *, const char *) = dlsym(samba, "_talloc_free");
    if (!db_open || !setattr || !release) {
        fputs("required Bookworm Samba ACL ABI is unavailable\n", stderr);
        return 1;
    }

    /* The legacy wrapper uses a 50,000-bucket hash and lock-order 2. Flags
     * 0 select a persistent local TDB (not clear-if-first or no-locking).
     * O_CREAT is needed to initialize an already-open empty database inode.
     */
    struct db_context *db = db_open(NULL, "/proc/self/fd/4", 50000, 0,
                                    O_RDWR | O_CREAT, 0600, 2, 0);
    if (!db) {
        return fail("open inherited Samba xattr database");
    }

    errno = 0;
    if (setattr(db, id, "security.NTACL", blob, size, 0) != 0) {
        return fail("write Samba security.NTACL");
    }
    if (release(db, "DomainShare ACL write") != 0) {
        return fail("close Samba database context after security.NTACL write");
    }

    if (fchmod(DATABASE_FD, 0600) < 0) {
        return fail("restrict inherited database mode after security.NTACL write");
    }
    if (close(DATABASE_FD) < 0) {
        return fail("close inherited database after security.NTACL write");
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "file") != 0 && strcmp(argv[1], "directory") != 0)) {
        fputs("usage: domainshare-sambaacl file|directory (inherited fds 3 and 4)\n", stderr);
        return 1;
    }

    struct stat data, database;
    if (fstat(TARGET_FD, &data) < 0 || fstat(DATABASE_FD, &database) < 0) {
        return fail("inspect inherited descriptors");
    }

    int want_directory = strcmp(argv[1], "directory") == 0;
    if (!(want_directory ? S_ISDIR(data.st_mode) : S_ISREG(data.st_mode))) {
        fputs("inherited target descriptor does not match the expected file type\n", stderr);
        return 1;
    }
    if (!S_ISREG(database.st_mode) || database.st_uid != geteuid() || database.st_nlink != 1 ||
        (data.st_dev == database.st_dev && data.st_ino == database.st_ino)) {
        fputs("invalid inherited Samba database descriptor\n", stderr);
        return 1;
    }

    int flags = fcntl(DATABASE_FD, F_GETFL);
    if (flags < 0) {
        return fail("inspect inherited database access mode");
    }
    if ((flags & O_ACCMODE) != O_RDWR) {
        fputs("inherited database descriptor must be opened read-write\n", stderr);
        return 1;
    }

    unsigned char blob[MAX_BLOB + 1];
    size_t size = fread(blob, 1, sizeof(blob), stdin);
    if (ferror(stdin)) {
        return fail("read NTACL blob");
    }

    if (!has_managed_header(blob, size)) {
        fputs("invalid managed NTACL version 1 blob\n", stderr);
        return 1;
    }

    const struct file_id id = { .device = data.st_dev, .inode = data.st_ino };
    return persist(&id, blob, size);
}
