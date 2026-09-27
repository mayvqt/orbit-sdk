#ifndef ORBIT_MACOS_NATIVE_H
#define ORBIT_MACOS_NATIVE_H

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>

struct orbit_file_info {
    uint64_t device;
    uint64_t inode;
    uint64_t links;
    uint64_t size;
    uint32_t owner;
    uint32_t mode;
    uint32_t kind;
};

enum {
    ORBIT_OPEN_READ = 1,
    ORBIT_OPEN_WRITE = 2,
    ORBIT_OPEN_CREATE_EXCLUSIVE = 4,
    ORBIT_OPEN_NONBLOCK = 8
};

static inline void orbit_set_error(int *error_out) {
    if (error_out != NULL) *error_out = errno;
}

static inline int orbit_mach_timebase(uint32_t *numerator, uint32_t *denominator) {
    mach_timebase_info_data_t information = {0, 0};
    if (mach_timebase_info(&information) != KERN_SUCCESS || information.numer == 0 || information.denom == 0) return -1;
    *numerator = information.numer;
    *denominator = information.denom;
    return 0;
}
static inline uint64_t orbit_mach_continuous_time(void) { return mach_continuous_time(); }
static inline uint64_t orbit_mach_awake_time(void) { return mach_absolute_time(); }

static inline int orbit_platform_uuid(char *buffer, size_t capacity, size_t *value_length) {
    if (buffer == NULL || capacity < 2 || value_length == NULL) return -1;
    *value_length = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOPlatformExpertDevice");
    if (matching == NULL) return -1;
    io_service_t service = IOServiceGetMatchingService(0, matching);
    if (service == IO_OBJECT_NULL) return -1;
    CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, "IOPlatformUUID", kCFStringEncodingUTF8);
    CFTypeRef value = NULL;
    int result = -1;
    if (key != NULL) value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    if (value != NULL && CFGetTypeID(value) == CFStringGetTypeID()) {
        CFStringRef string = (CFStringRef)value;
        CFIndex length = CFStringGetLength(string);
        if (length > 0 && length <= 256 && (size_t)length < capacity && CFStringGetCString(string, buffer, (CFIndex)capacity, kCFStringEncodingUTF8)) {
            size_t bytes = strlen(buffer);
            int ascii = 1;
            for (size_t index = 0; index < bytes; index++) {
                if ((unsigned char)buffer[index] > 0x7f) { ascii = 0; break; }
            }
            if (bytes == (size_t)length && ascii) {
                *value_length = bytes;
                result = 0;
            }
        }
    }
    if (value != NULL) CFRelease(value);
    if (key != NULL) CFRelease(key);
    IOObjectRelease(service);
    return result;
}

static inline int orbit_open_root_directory(int *error_out) {
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) orbit_set_error(error_out);
    return fd;
}
static inline int orbit_open_directory_at(int parent, const char *name, int *error_out) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) orbit_set_error(error_out);
    return fd;
}
static inline int orbit_make_directory_at(int parent, const char *name, int *error_out) {
    if (mkdirat(parent, name, 0700) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}
static inline int orbit_open_file_at(int parent, const char *name, int flags, unsigned mode, int *error_out) {
    int native_flags = O_NOFOLLOW | O_CLOEXEC;
    if (flags & ORBIT_OPEN_READ) native_flags |= O_RDONLY;
    if (flags & ORBIT_OPEN_WRITE) native_flags = (native_flags & ~O_RDONLY) | O_RDWR;
    if (flags & ORBIT_OPEN_CREATE_EXCLUSIVE) native_flags |= O_CREAT | O_EXCL;
    if (flags & ORBIT_OPEN_NONBLOCK) native_flags |= O_NONBLOCK;
    int fd = openat(parent, name, native_flags, (mode_t)mode);
    if (fd < 0) orbit_set_error(error_out);
    return fd;
}
static inline void orbit_info(const struct stat *st, struct orbit_file_info *information) {
    information->device = (uint64_t)st->st_dev;
    information->inode = (uint64_t)st->st_ino;
    information->links = (uint64_t)st->st_nlink;
    information->size = st->st_size < 0 ? 0 : (uint64_t)st->st_size;
    information->owner = (uint32_t)st->st_uid;
    information->mode = (uint32_t)st->st_mode;
    information->kind = S_ISDIR(st->st_mode) ? 1u : S_ISREG(st->st_mode) ? 2u : 3u;
}
static inline int orbit_stat_fd(int fd, struct orbit_file_info *information, int *error_out) {
    struct stat st;
    if (fstat(fd, &st) != 0) { orbit_set_error(error_out); return -1; }
    orbit_info(&st, information);
    return 0;
}
static inline int orbit_stat_at(int parent, const char *name, struct orbit_file_info *information, int *error_out) {
    struct stat st;
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) != 0) { orbit_set_error(error_out); return -1; }
    orbit_info(&st, information);
    return 0;
}
static inline int orbit_filesystem_is_local(int fd, int *error_out) {
    struct statfs information;
    if (fstatfs(fd, &information) != 0) { orbit_set_error(error_out); return -1; }
    return (information.f_flags & MNT_LOCAL) != 0;
}
static inline int orbit_lock_exclusive_nonblocking(int fd, int *error_out) {
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}
static inline int orbit_is_would_block(int error_number) { return error_number == EWOULDBLOCK || error_number == EAGAIN; }
static inline int orbit_rename_at(int old_parent, const char *old_name, int new_parent, const char *new_name, int *error_out) {
    if (renameat(old_parent, old_name, new_parent, new_name) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}
static inline int orbit_unlink_at(int parent, const char *name, int *error_out) {
    if (unlinkat(parent, name, 0) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}
static inline int orbit_sync_directory(int fd, int *error_out) {
    if (fsync(fd) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}
static inline int orbit_full_sync_file(int fd, int *error_out) {
    if (fcntl(fd, F_FULLFSYNC) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}
static inline int orbit_truncate_file(int fd, int *error_out) {
    if (ftruncate(fd, 0) == 0) return 0;
    orbit_set_error(error_out);
    return -1;
}

#endif
