#pragma once
#include <ares.h>

typedef struct {
   void *handle;
} ares_impl_t;

extern ares_impl_t impl;

void load_cares_impl(const char *path);
void unload_cares_impl();

// Declarations for things not in the system ares.h

#ifndef ARES_OPT_SERVER_FAILOVER
#define ARES_OPT_SERVER_FAILOVER (1 << 23)
#endif

// Server failover options (not in system ares.h)
struct ares_server_failover_options {
  unsigned short retry_chance;
  size_t retry_delay;
};

// Extended ares_options that includes server_failover_opts
// Must match the Rust ares_options struct layout
struct ares_options_ext {
  struct ares_options base;
  struct ares_server_failover_options server_failover_opts;
};

// Callback type for ares_query_dnsrec / ares_search_dnsrec (not in system header)
#ifndef HAVE_ARES_CALLBACK_DNSREC
typedef void (*ares_callback_dnsrec)(void *arg, ares_status_t status,
                                     size_t timeouts,
                                     const ares_dns_record_t *dnsrec);
#endif

// Server state callback (not in system header)
#ifndef HAVE_ARES_SERVER_STATE_CALLBACK
typedef void (*ares_server_state_callback)(const char *server_string,
                                           ares_bool_t success,
                                           int flags, void *data);
#endif

#ifndef ARES_SERV_STATE_UDP
#define ARES_SERV_STATE_UDP (1 << 0)
#endif
#ifndef ARES_SERV_STATE_TCP
#define ARES_SERV_STATE_TCP (1 << 1)
#endif

// DNS OPT option IDs (may not be in system header)
#ifndef ARES_OPT_PARAM_COOKIE
#define ARES_OPT_PARAM_COOKIE 10
#endif

// Function declarations not in system header
#ifdef __cplusplus
extern "C" {
#endif

void        ares_query_dnsrec(ares_channel_t *channel, const char *name,
                              ares_dns_class_t dnsclass, ares_dns_rec_type_t type,
                              ares_callback_dnsrec callback, void *arg,
                              unsigned short *qid);
void        ares_search_dnsrec(ares_channel_t *channel,
                               const ares_dns_record_t *dnsrec,
                               ares_callback_dnsrec callback, void *arg);
void        ares_set_server_state_callback(ares_channel_t *channel,
                                           ares_server_state_callback callback,
                                           void *data);

ares_dns_record_t *ares_dns_record_duplicate(const ares_dns_record_t *dnsrec);

// Functions from c-ares 1.34.6 not in system header
const char         *ares_dns_opcode_tostr(ares_dns_opcode_t opcode);
const char         *ares_dns_rcode_tostr(ares_dns_rcode_t rcode);
const char         *ares_dns_section_tostr(ares_dns_section_t section);
ares_dns_class_t    ares_dns_rr_get_class(const ares_dns_rr_t *rr);
unsigned int        ares_dns_rr_get_ttl(const ares_dns_rr_t *rr);
const struct in_addr *ares_dns_rr_get_addr(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
const struct ares_in6_addr *ares_dns_rr_get_addr6(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
const char         *ares_dns_rr_get_str(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
unsigned char       ares_dns_rr_get_u8(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
unsigned short      ares_dns_rr_get_u16(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
unsigned int        ares_dns_rr_get_u32(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
size_t              ares_dns_rr_get_abin_cnt(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
const unsigned char *ares_dns_rr_get_abin(const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                          size_t idx, size_t *len);
void                ares_free(void *ptr);

#ifdef __cplusplus
}
#endif
