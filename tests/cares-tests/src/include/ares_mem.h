/* Stub for internal ares_mem.h.
   Provides declarations for functions not in the system ares.h
   that ares-test-fuzz.c needs in modern (non-legacy) mode. */
#ifndef ARES_MEM_H
#define ARES_MEM_H

#include <stdlib.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

void ares_free(void *ptr);

/* Enum values from c-ares 1.34.6 not in system ares_dns_record.h */
#ifndef ARES_DATATYPE_ABINP
#define ARES_DATATYPE_ABINP 11
#endif

/* Functions from c-ares 1.34.6 not in system ares_dns_record.h */
size_t ares_dns_rr_get_abin_cnt(const ares_dns_rr_t *dns_rr,
                                ares_dns_rr_key_t key);
const unsigned char *ares_dns_rr_get_abin(const ares_dns_rr_t *dns_rr,
                                          ares_dns_rr_key_t key,
                                          size_t idx, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* ARES_MEM_H */
