#ifndef ORBIT_PROFILE_H
#define ORBIT_PROFILE_H
#if defined(ORBIT_ENABLE_OFFLINE) && !defined(ORBIT_ENABLE_SERVICES)
#define ORBIT_ENABLE_SERVICES 1
#endif
#ifdef ORBIT_ENABLE_OFFLINE
#ifndef ORBIT_OFFLINE_PROFILE_FILE_BYTES
#define ORBIT_OFFLINE_PROFILE_FILE_BYTES 4096u
#endif
#if ORBIT_OFFLINE_PROFILE_FILE_BYTES != 4096 &&                                \
    ORBIT_OFFLINE_PROFILE_FILE_BYTES != 16384
#error "Offline profile accepts exactly 4096 or 16384 signed-file bytes"
#endif
#define ORBIT_PROFILE_RECORD_BYTES (1024u + ORBIT_OFFLINE_PROFILE_FILE_BYTES)
#define ORBIT_PROFILE_SLOT_BYTES(erase_bytes)                                  \
  (((64u + ORBIT_PROFILE_RECORD_BYTES + (erase_bytes) - 1u) / (erase_bytes)) * \
   (erase_bytes))
#else
#define ORBIT_PROFILE_RECORD_BYTES 1024u
#define ORBIT_PROFILE_SLOT_BYTES(erase_bytes) (erase_bytes)
#endif
#endif
