#pragma once
#include <ares.h>

typedef struct {
   void *handle;
} ares_impl_t;

extern ares_impl_t impl;

void load_cares_impl(const char *path);
void unload_cares_impl();

// Function declarations not in ares.h (our custom additions)
#ifdef __cplusplus
extern "C" {
#endif

ares_dns_record_t *ares_dns_record_duplicate(const ares_dns_record_t *dnsrec);

#ifdef __cplusplus
}
#endif
