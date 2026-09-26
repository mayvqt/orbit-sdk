#define _GNU_SOURCE
#include "orbit_posix.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(void) {
  char path[] = "/tmp/orbit-posix-test-XXXXXX";
  CHECK(mkdtemp(path) != NULL);
  int dir = open(path, O_RDONLY | O_DIRECTORY);
  CHECK(dir >= 0);
  orbit_posix_t a, b;
  orbit_client_services_t s, other;
  CHECK(orbit_posix_open(&a, dir, &s) == 0);
  CHECK(orbit_posix_open(&b, dir, &other) == ORBIT_CLIENT_STORAGE);
  uint8_t record[64] = {0}, out[64];
  uint32_t length = 99;
  CHECK(s.load(s.context, out, sizeof(out), &length) ==
            ORBIT_CLIENT_NOT_FOUND &&
        length == 0);
  memcpy(record, "ORBITMC1", 8);
  record[8] = 1;
  CHECK(s.commit(s.context, 0, record, sizeof(record)) == 0);
  CHECK(s.commit(s.context, 0, record, sizeof(record)) == ORBIT_CLIENT_STALE);
  CHECK(s.load(s.context, out, sizeof(out), &length) == 0 &&
        length == sizeof(record) && !memcmp(out, record, length));
  orbit_posix_close(&a);
  CHECK(orbit_posix_open(&a, dir, &s) == 0);
  CHECK(s.load(s.context, out, sizeof(out), &length) == 0);
  uint8_t damaged = 0;
  CHECK(pwrite(a.descriptor, &damaged, 1, 64) == 1);
  CHECK(s.load(s.context, out, sizeof(out), &length) == ORBIT_CLIENT_STORAGE);
  orbit_posix_close(&a);
  CHECK(unlinkat(dir, "orbit-journal.bin", 0) == 0);
  CHECK(symlinkat("/etc/passwd", dir, "orbit-journal.bin") == 0);
  CHECK(orbit_posix_open(&a, dir, &s) == ORBIT_CLIENT_STORAGE);
  CHECK(unlinkat(dir, "orbit-journal.bin", 0) == 0);
  CHECK(fchmod(dir, 0770) == 0);
  CHECK(orbit_posix_open(&a, dir, &s) == ORBIT_CLIENT_STORAGE);
  close(dir);
  CHECK(rmdir(path) == 0);
  puts("POSIX storage: exclusive ownership, durable generation, corruption and "
       "symlink guards passed");
  return 0;
}
