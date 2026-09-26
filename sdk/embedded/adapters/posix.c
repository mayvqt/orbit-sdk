#define _GNU_SOURCE
#include "orbit_posix.h"
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int32_t file_read(void *p, uint8_t slot, uint32_t offset, uint8_t *bytes,
                         uint32_t length) {
  orbit_posix_t *c = p;
  uint32_t at = 0u;
  ssize_t n;
  if (slot > 1u || offset > 4096u || length > 4096u - offset)
    return ORBIT_CLIENT_STORAGE;
  while (at < length) {
    n = pread(c->descriptor, bytes + at, length - at,
              (off_t)slot * 4096 + offset + at);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return ORBIT_CLIENT_STORAGE;
    at += (uint32_t)n;
  }
  return 0;
}
static int32_t file_write(void *p, uint8_t slot, uint32_t offset,
                          const uint8_t *bytes, uint32_t length) {
  orbit_posix_t *c = p;
  uint32_t at = 0u;
  ssize_t n;
  if (slot > 1u || offset > 4096u || length > 4096u - offset)
    return ORBIT_CLIENT_STORAGE;
  while (at < length) {
    n = pwrite(c->descriptor, bytes + at, length - at,
               (off_t)slot * 4096 + offset + at);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return ORBIT_CLIENT_STORAGE;
    at += (uint32_t)n;
  }
  return 0;
}
static int32_t file_erase(void *p, uint8_t slot) {
  uint8_t bytes[256];
  uint32_t at;
  memset(bytes, 255, sizeof(bytes));
  for (at = 0u; at < 4096u; at += sizeof(bytes))
    if (file_write(p, slot, at, bytes, sizeof(bytes)) != 0)
      return ORBIT_CLIENT_STORAGE;
  return 0;
}
static int32_t file_sync(void *p) {
  return fsync(((orbit_posix_t *)p)->descriptor) == 0 ? 0
                                                      : ORBIT_CLIENT_STORAGE;
}
static int32_t load(void *p, uint8_t *bytes, uint32_t capacity,
                    uint32_t *length) {
  return orbit_journal_load(&((orbit_posix_t *)p)->journal, bytes, capacity,
                            length);
}
static int32_t commit(void *p, uint64_t version, const uint8_t *bytes,
                      uint32_t length) {
  return orbit_journal_commit(&((orbit_posix_t *)p)->journal, version, bytes,
                              length);
}
int32_t orbit_posix_clock(void *p, int64_t *seconds, uint64_t *milliseconds) {
  struct timespec utc, boot;
  (void)p;
  if (clock_gettime(CLOCK_REALTIME, &utc) != 0 ||
      clock_gettime(CLOCK_BOOTTIME, &boot) != 0 || utc.tv_sec < 0 ||
      boot.tv_sec < 0)
    return ORBIT_CLIENT_CLOCK;
  *seconds = (int64_t)utc.tv_sec;
  *milliseconds =
      (uint64_t)boot.tv_sec * 1000u + (uint64_t)boot.tv_nsec / 1000000u;
  return 0;
}
int32_t orbit_posix_entropy(void *p, uint8_t *bytes, uint32_t length) {
  uint32_t at = 0u;
  ssize_t n;
  (void)p;
  while (at < length) {
    n = getrandom(bytes + at, length - at, 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return ORBIT_CLIENT_UNTRUSTED;
    at += (uint32_t)n;
  }
  return 0;
}
typedef struct receiver {
  CURL *curl;
  uint16_t *http;
  orbit_receive_fn receive;
  void *context;
  int32_t error;
  uint32_t total;
  uint32_t request_length;
} receiver_t;
static size_t receive_bytes(char *bytes, size_t size, size_t count, void *p) {
  receiver_t *r = p;
  long status = 0;
  curl_off_t uploaded = 0;
  size_t n;
  if (size != 0u && count > SIZE_MAX / size)
    return 0u;
  n = size * count;
  if (r->request_length && (curl_easy_getinfo(r->curl, CURLINFO_SIZE_UPLOAD_T,
                                              &uploaded) != CURLE_OK ||
                            uploaded < r->request_length)) {
    r->error = ORBIT_CLIENT_UNTRUSTED;
    return 0;
  }
  if (n > ORBIT_CLIENT_ARENA_BYTES - r->total) {
    r->error = ORBIT_CLIENT_RESOURCE_LIMIT;
    return 0u;
  }
  if (curl_easy_getinfo(r->curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
      status < 100 || status > 599) {
    r->error = ORBIT_CLIENT_UNTRUSTED;
    return 0u;
  }
  *r->http = (uint16_t)status;
  r->total += (uint32_t)n;
  r->error = r->receive(r->context, (const uint8_t *)bytes, (uint32_t)n);
  return r->error ? 0u : n;
}
int32_t orbit_posix_exchange(void *p, const orbit_http_request_t *request,
                             uint16_t *http, orbit_receive_fn receive,
                             void *context) {
  char url[1025];
  CURL *curl = NULL;
  struct curl_slist *headers = NULL;
  CURLcode code;
  long status = 0;
  int32_t result = ORBIT_CLIENT_UNTRUSTED;
  receiver_t r;
  uint32_t length;
  (void)p;
  if (!request || !http || !receive || !request->origin.data ||
      !request->path.data || (!request->body.data && request->body.length) ||
      request->origin.length > 512u || request->path.length > 512u ||
      request->body.length > ORBIT_CLIENT_ARENA_BYTES || request->post > 1u ||
      request->origin.length < 8u ||
      memcmp(request->origin.data, "https://", 8u) != 0 ||
      request->path.length == 0u || request->path.data[0] != '/')
    return ORBIT_CLIENT_ARGUMENT;
  length = request->origin.length + request->path.length;
  memcpy(url, request->origin.data, request->origin.length);
  memcpy(url + request->origin.length, request->path.data,
         request->path.length);
  url[length] = 0;
  *http = 0u;
  curl = curl_easy_init();
  if (curl == NULL)
    return result;
  r = (receiver_t){curl,
                   http,
                   receive,
                   context,
                   0,
                   0u,
                   request->post ? request->body.length : 0u};
  headers = curl_slist_append(NULL, "Content-Type: application/json");
  if (headers == NULL)
    goto done;
  {
    struct curl_slist *more =
        curl_slist_append(headers, "Accept: application/json");
    if (more == NULL)
      goto done;
    headers = more;
  }
#define SET(option, value)                                                     \
  do {                                                                         \
    if (curl_easy_setopt(curl, (option), (value)) != CURLE_OK)                 \
      goto done;                                                               \
  } while (0)
  SET(CURLOPT_URL, url);
  SET(CURLOPT_PROTOCOLS_STR, "https");
  SET(CURLOPT_FOLLOWLOCATION, 0L);
  SET(CURLOPT_MAXREDIRS, 0L);
  SET(CURLOPT_SSL_VERIFYPEER, 1L);
  SET(CURLOPT_SSL_VERIFYHOST, 2L);
  SET(CURLOPT_TIMEOUT_MS, 30000L);
  SET(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
  SET(CURLOPT_NOSIGNAL, 1L);
  SET(CURLOPT_HTTPHEADER, headers);
  SET(CURLOPT_ACCEPT_ENCODING, "identity");
  SET(CURLOPT_HTTP_CONTENT_DECODING, 0L);
  SET(CURLOPT_WRITEFUNCTION, receive_bytes);
  SET(CURLOPT_WRITEDATA, &r);
  if (request->post) {
    SET(CURLOPT_POST, 1L);
    SET(CURLOPT_POSTFIELDS, request->body.data
                                ? (const void *)request->body.data
                                : (const void *)"");
    SET(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)request->body.length);
  }
  code = curl_easy_perform(curl);
  if (r.error) {
    result = r.error;
    goto done;
  }
  if (code == CURLE_OPERATION_TIMEDOUT || code == CURLE_COULDNT_CONNECT ||
      code == CURLE_COULDNT_RESOLVE_HOST) {
    result = ORBIT_CLIENT_TRANSIENT;
    goto done;
  }
  if (code != CURLE_OK ||
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
      status < 100 || status > 599)
    goto done;
  *http = (uint16_t)status;
  result = 0;
done:
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return result;
#undef SET
}
int32_t orbit_posix_open(orbit_posix_t *c, int directory_fd,
                         orbit_client_services_t *services) {
  struct stat info;
  int fd, created = 0;
  uint8_t marker;
  if (c == NULL || services == NULL || fstat(directory_fd, &info) != 0 ||
      !S_ISDIR(info.st_mode) || info.st_uid != getuid() ||
      (info.st_mode & 077u) != 0u)
    return ORBIT_CLIENT_STORAGE;
  memset(c, 0, sizeof(*c));
  c->descriptor = -1;
  fd = openat(directory_fd, "orbit-journal.bin",
              O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd >= 0)
    created = 1;
  else if (errno == EEXIST)
    fd = openat(directory_fd, "orbit-journal.bin",
                O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return ORBIT_CLIENT_STORAGE;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_uid != getuid() || (info.st_mode & 077u) != 0u ||
      info.st_nlink != 1 || flock(fd, LOCK_EX | LOCK_NB) != 0) {
    close(fd);
    return ORBIT_CLIENT_STORAGE;
  }
  c->descriptor = fd;
  c->journal =
      (orbit_journal_t){c, 4096u, file_read, file_erase, file_write, file_sync};
  if (created) {
    if (file_erase(c, 0u) != 0 || file_erase(c, 1u) != 0 || file_sync(c) != 0 ||
        fsync(directory_fd) != 0)
      goto failed;
  } else if (info.st_size != 8192 || pread(fd, &marker, 1u, 0) != 1)
    goto failed;
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    goto failed;
  *services = (orbit_client_services_t){c,
                                        orbit_posix_exchange,
                                        orbit_posix_clock,
                                        orbit_posix_entropy,
                                        load,
                                        commit,
                                        *orbit_openssl_crypto()};
  return 0;
failed:
  close(fd);
  c->descriptor = -1;
  return ORBIT_CLIENT_STORAGE;
}
void orbit_posix_close(orbit_posix_t *c) {
  if (c != NULL && c->descriptor >= 0) {
    close(c->descriptor);
    c->descriptor = -1;
    curl_global_cleanup();
  }
}
