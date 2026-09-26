#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

int orbit_open(const char *path, int flags, uint32_t mode) {
    return open(path, flags, (mode_t)mode);
}

int orbit_openat(int directory, const char *path, int flags, uint32_t mode) {
    return openat(directory, path, flags, (mode_t)mode);
}
