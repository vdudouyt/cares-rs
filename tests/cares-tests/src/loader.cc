#include <dlfcn.h>
#include <assert.h>
#include <stdexcept>
#include "loader.h"

#define IMPL_SHIM(RET, FUNC, PARAMS, ARGS)                              \
    RET FUNC PARAMS {                                                   \
        RET (*fn) PARAMS = (RET (*) PARAMS) dlsym(impl.handle, #FUNC);  \
        if (!fn) {                                                      \
            throw std::runtime_error("not implemented: " #FUNC);        \
        }                                                               \
        return fn ARGS;                                                 \
    }

ares_impl_t impl;

void load_cares_impl(const char *path) {
   impl.handle = dlopen(path, RTLD_LAZY);
   assert(impl.handle);
}

void unload_cares_impl() {
   dlclose(impl.handle);
}

IMPL_SHIM(void, ares_free_hostent, (struct hostent *host), (host))
IMPL_SHIM(int, ares_parse_a_reply, (const unsigned char *abuf, int alen, struct hostent **host, struct ares_addrttl *addrttls, int *naddrttls), (abuf, alen, host, addrttls, naddrttls))
IMPL_SHIM(int, ares_parse_aaaa_reply, (const unsigned char *abuf, int alen, struct hostent **host, struct ares_addr6ttl *addrttls, int *naddrttls), (abuf, alen, host, addrttls, naddrttls))
IMPL_SHIM(void, ares_free_data, (void *dataptr), (dataptr))
IMPL_SHIM(int, ares_parse_caa_reply, (const unsigned char *abuf, int alen, struct ares_caa_reply **caa_out), (abuf, alen, caa_out))
IMPL_SHIM(int, ares_parse_mx_reply, (const unsigned char *abuf, int alen, struct ares_mx_reply **mx_out), (abuf, alen, mx_out))
IMPL_SHIM(int, ares_parse_naptr_reply, (const unsigned char *abuf, int alen, struct ares_naptr_reply **naptr_out), (abuf, alen, naptr_out))
IMPL_SHIM(int, ares_parse_ns_reply, (const unsigned char *abuf, int alen, struct hostent **host), (abuf, alen, host))
IMPL_SHIM(int, ares_parse_ptr_reply, (const unsigned char *abuf, int alen, const void *addr, int addrlen, int family, struct hostent **host), (abuf, alen, addr, addrlen, family, host))
IMPL_SHIM(int, ares_parse_soa_reply, (const unsigned char *abuf, int alen, struct ares_soa_reply **soa_out), (abuf, alen, soa_out))
IMPL_SHIM(int, ares_parse_srv_reply, (const unsigned char *abuf, int alen, struct ares_srv_reply **srv_out), (abuf, alen, srv_out))
IMPL_SHIM(int, ares_parse_txt_reply, (const unsigned char *abuf, int alen, struct ares_txt_reply **txt_out), (abuf, alen, txt_out))
IMPL_SHIM(int, ares_parse_uri_reply, (const unsigned char *abuf, int alen, struct ares_uri_reply **uri_out), (abuf, alen, uri_out))
IMPL_SHIM(int, ares_parse_txt_reply_ext, (const unsigned char *abuf, int alen, struct ares_txt_ext **txt_out), (abuf, alen, txt_out))

IMPL_SHIM(void, ares_set_socket_functions, (ares_channel_t *channel, const struct ares_socket_functions *funcs, void *user_data), (channel, funcs, user_data));
IMPL_SHIM(void, ares_gethostbyname, (ares_channel_t *channel, const char *name, int family, ares_host_callback callback, void *arg), (channel, name, family, callback, arg));
IMPL_SHIM(int, ares_init_options, (ares_channel_t **channelptr, const struct ares_options *options, int optmask), (channelptr, options, optmask));
IMPL_SHIM(void, ares_destroy, (ares_channel_t *channel), (channel));
IMPL_SHIM(struct timeval *, ares_timeout, (ares_channel_t *channel, struct timeval *maxtv, struct timeval *tv), (channel, maxtv, tv));
IMPL_SHIM(void, ares_cancel, (ares_channel_t *channel), (channel));
IMPL_SHIM(void, ares_process, (ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds), (channel, read_fds, write_fds));
IMPL_SHIM(int, ares_fds, (ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds), (channel, read_fds, write_fds));
IMPL_SHIM(int, ares_gethostbyname_file, (ares_channel_t *channel, const char *name, int family, struct hostent **host), (channel, name, family, host));
IMPL_SHIM(void, ares_gethostbyaddr, (ares_channel_t *channel, const void *addr, int addrlen, int family, ares_host_callback callback, void *arg), (channel, addr, addrlen, family, callback, arg));
IMPL_SHIM(void, ares_search, (ares_channel_t *channel, const char *name, int dnsclass, int type, ares_callback callback, void *arg), (channel, name, dnsclass, type, callback, arg));
IMPL_SHIM(void, ares_getnameinfo, (ares_channel_t *channel, const struct sockaddr *sa, ares_socklen_t salen, int flags, ares_nameinfo_callback callback, void *arg), (channel, sa, salen, flags, callback, arg));
IMPL_SHIM(int, ares_getsock, (ares_channel_t *channel, ares_socket_t *socks, int numsocks), (channel, socks, numsocks));
IMPL_SHIM(int, ares_dup, (ares_channel_t **dest, ares_channel_t *src), (dest, src));
IMPL_SHIM(int, ares_set_servers, (ares_channel_t *channel, const struct ares_addr_node *servers), (channel, servers));
IMPL_SHIM(int, ares_set_servers_ports, (ares_channel_t *channel, const struct ares_addr_port_node *servers), (channel, servers));
IMPL_SHIM(int, ares_set_servers_csv, (ares_channel_t *channel, const char *servers), (channel, servers));
IMPL_SHIM(int, ares_set_servers_ports_csv, (ares_channel_t *channel, const char *servers), (channel, servers));

IMPL_SHIM(void, ares_getaddrinfo, (ares_channel_t *channel, const char *node, const char *service, const struct ares_addrinfo_hints *hints, ares_addrinfo_callback callback, void *arg), (channel, node, service, hints, callback, arg));
IMPL_SHIM(int, ares_inet_pton, (int af, const char *src, void *dst), (af, src, dst));
IMPL_SHIM(void, ares_freeaddrinfo, (struct ares_addrinfo *ai), (ai));
IMPL_SHIM(int, ares_expand_name, (const unsigned char *encoded, const unsigned char *abuf, int alen, char **s, long *enclen), (encoded, abuf, alen, s, enclen));
IMPL_SHIM(void, ares_free_string, (void *str), (str));

IMPL_SHIM(void, ares_set_local_dev, (ares_channel_t *channel, const char *local_dev_name), (channel, local_dev_name));
IMPL_SHIM(void, ares_set_local_ip4, (ares_channel_t *channel, unsigned int local_ip), (channel, local_ip));
IMPL_SHIM(void, ares_set_local_ip6, (ares_channel_t *channel, const unsigned char *local_ip6), (channel, local_ip6));
IMPL_SHIM(int, ares_save_options, (ares_channel_t *channel, struct ares_options *options, int *optmask), (channel, options, optmask));
IMPL_SHIM(void, ares_destroy_options, (struct ares_options *options), (options));

// Library init/cleanup
IMPL_SHIM(int, ares_library_init, (int flags), (flags));
IMPL_SHIM(void, ares_library_cleanup, (void), ());
IMPL_SHIM(int, ares_init, (ares_channel_t **channelptr), (channelptr));

// Info/error
IMPL_SHIM(const char *, ares_strerror, (int code), (code));
IMPL_SHIM(const char *, ares_version, (int *version), (version));

// Query construction
IMPL_SHIM(int, ares_mkquery, (const char *name, int dnsclass, int type, unsigned short id, int rd, unsigned char **buf, int *buflen), (name, dnsclass, type, id, rd, buf, buflen));
IMPL_SHIM(int, ares_create_query, (const char *name, int dnsclass, int type, unsigned short id, int rd, unsigned char **buf, int *buflen, int max_udp_size), (name, dnsclass, type, id, rd, buf, buflen, max_udp_size));

// Query sending
IMPL_SHIM(void, ares_send, (ares_channel_t *channel, const unsigned char *qbuf, int qlen, ares_callback callback, void *arg), (channel, qbuf, qlen, callback, arg));

// DNS string expansion
IMPL_SHIM(int, ares_expand_string, (const unsigned char *encoded, const unsigned char *abuf, int alen, unsigned char **s, long *enclen), (encoded, abuf, alen, s, enclen));

// Address conversion
IMPL_SHIM(const char *, ares_inet_ntop, (int af, const void *src, char *dst, ares_socklen_t size), (af, src, dst, size));

// Channel configuration
IMPL_SHIM(ares_status_t, ares_reinit, (ares_channel_t *channel), (channel));
IMPL_SHIM(int, ares_set_sortlist, (ares_channel_t *channel, const char *sortlist), (channel, sortlist));
IMPL_SHIM(char *, ares_get_servers_csv, (ares_channel_t *channel), (channel));
IMPL_SHIM(int, ares_get_servers, (ares_channel_t *channel, struct ares_addr_node **servers), (channel, servers));

// Callback registration
IMPL_SHIM(void, ares_set_socket_callback, (ares_channel_t *channel, ares_sock_create_callback callback, void *user_data), (channel, callback, user_data));
IMPL_SHIM(void, ares_set_socket_configure_callback, (ares_channel_t *channel, ares_sock_config_callback callback, void *user_data), (channel, callback, user_data));
IMPL_SHIM(void, ares_set_server_state_callback, (ares_channel_t *channel, ares_server_state_callback callback, void *data), (channel, callback, data));

// Library state
IMPL_SHIM(int, ares_library_initialized, (void), ());

// Active query count
IMPL_SHIM(size_t, ares_queue_active_queries, (ares_channel_t *channel), (channel));

// Query
IMPL_SHIM(void, ares_query, (ares_channel_t *channel, const char *name, int dnsclass, int type, ares_callback callback, void *arg), (channel, name, dnsclass, type, callback, arg));

// DNS record query/search
IMPL_SHIM(void, ares_query_dnsrec, (ares_channel_t *channel, const char *name, ares_dns_class_t dnsclass, ares_dns_rec_type_t type, ares_callback_dnsrec callback, void *arg, unsigned short *qid), (channel, name, dnsclass, type, callback, arg, qid));
IMPL_SHIM(void, ares_search_dnsrec, (ares_channel_t *channel, const ares_dns_record_t *dnsrec, ares_callback_dnsrec callback, void *arg), (channel, dnsrec, callback, arg));

// DNS record lifecycle
IMPL_SHIM(ares_status_t, ares_dns_record_create, (ares_dns_record_t **dnsrec, unsigned short id, unsigned short flags, ares_dns_opcode_t opcode, ares_dns_rcode_t rcode), (dnsrec, id, flags, opcode, rcode));
IMPL_SHIM(void, ares_dns_record_destroy, (ares_dns_record_t *dnsrec), (dnsrec));
IMPL_SHIM(ares_dns_record_t *, ares_dns_record_duplicate, (const ares_dns_record_t *dnsrec), (dnsrec));

// DNS record header
IMPL_SHIM(unsigned short, ares_dns_record_get_id, (const ares_dns_record_t *dnsrec), (dnsrec));
IMPL_SHIM(unsigned short, ares_dns_record_get_flags, (const ares_dns_record_t *dnsrec), (dnsrec));
IMPL_SHIM(ares_dns_opcode_t, ares_dns_record_get_opcode, (const ares_dns_record_t *dnsrec), (dnsrec));
IMPL_SHIM(ares_dns_rcode_t, ares_dns_record_get_rcode, (const ares_dns_record_t *dnsrec), (dnsrec));
IMPL_SHIM(ares_status_t, ares_dns_record_set_id, (ares_dns_record_t *dnsrec, unsigned short id), (dnsrec, id));

// DNS record queries
IMPL_SHIM(ares_status_t, ares_dns_record_query_add, (ares_dns_record_t *dnsrec, const char *name, ares_dns_rec_type_t qtype, ares_dns_class_t qclass), (dnsrec, name, qtype, qclass));
IMPL_SHIM(size_t, ares_dns_record_query_cnt, (const ares_dns_record_t *dnsrec), (dnsrec));
IMPL_SHIM(ares_status_t, ares_dns_record_query_get, (const ares_dns_record_t *dnsrec, size_t idx, const char **name, ares_dns_rec_type_t *qtype, ares_dns_class_t *qclass), (dnsrec, idx, name, qtype, qclass));

// DNS record RR management
IMPL_SHIM(ares_status_t, ares_dns_record_rr_add, (ares_dns_rr_t **rr_out, ares_dns_record_t *dnsrec, ares_dns_section_t sect, const char *name, ares_dns_rec_type_t type, ares_dns_class_t rclass, unsigned int ttl), (rr_out, dnsrec, sect, name, type, rclass, ttl));
IMPL_SHIM(size_t, ares_dns_record_rr_cnt, (const ares_dns_record_t *dnsrec, ares_dns_section_t sect), (dnsrec, sect));
IMPL_SHIM(ares_dns_rr_t *, ares_dns_record_rr_get, (ares_dns_record_t *dnsrec, ares_dns_section_t sect, size_t idx), (dnsrec, sect, idx));
IMPL_SHIM(const ares_dns_rr_t *, ares_dns_record_rr_get_const, (const ares_dns_record_t *dnsrec, ares_dns_section_t sect, size_t idx), (dnsrec, sect, idx));

// DNS RR getters
IMPL_SHIM(const char *, ares_dns_rr_get_name, (const ares_dns_rr_t *dns_rr), (dns_rr));
IMPL_SHIM(ares_dns_rec_type_t, ares_dns_rr_get_type, (const ares_dns_rr_t *dns_rr), (dns_rr));
IMPL_SHIM(const unsigned char *, ares_dns_rr_get_bin, (const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key, size_t *len), (dns_rr, key, len));

// DNS RR setters
IMPL_SHIM(ares_status_t, ares_dns_rr_set_u8, (ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key, unsigned char val), (dns_rr, key, val));
IMPL_SHIM(ares_status_t, ares_dns_rr_set_u16, (ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key, unsigned short val), (dns_rr, key, val));
IMPL_SHIM(ares_status_t, ares_dns_rr_set_u32, (ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key, unsigned int val), (dns_rr, key, val));
IMPL_SHIM(ares_status_t, ares_dns_rr_set_opt, (ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key, unsigned short opt, const unsigned char *val, size_t val_len), (dns_rr, key, opt, val, val_len));
IMPL_SHIM(ares_bool_t, ares_dns_rr_get_opt_byid, (const ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key, unsigned short opt, const unsigned char **val, size_t *val_len), (dns_rr, key, opt, val, val_len));

// DNS parse/write
IMPL_SHIM(ares_status_t, ares_dns_parse, (const unsigned char *buf, size_t buf_len, unsigned int flags, ares_dns_record_t **dnsrec), (buf, buf_len, flags, dnsrec));
IMPL_SHIM(ares_status_t, ares_dns_write, (ares_dns_record_t *dnsrec, unsigned char **buf, size_t *buf_len), (dnsrec, buf, buf_len));

// DNS metadata
IMPL_SHIM(const char *, ares_dns_rec_type_tostr, (ares_dns_rec_type_t type), (type));
IMPL_SHIM(ares_bool_t, ares_dns_rec_type_fromstr, (ares_dns_rec_type_t *type, const char *str), (type, str));
IMPL_SHIM(const char *, ares_dns_rr_key_tostr, (ares_dns_rr_key_t key), (key));
IMPL_SHIM(ares_dns_datatype_t, ares_dns_rr_key_datatype, (ares_dns_rr_key_t key), (key));
IMPL_SHIM(ares_dns_rec_type_t, ares_dns_rr_key_to_rec_type, (ares_dns_rr_key_t key), (key));
IMPL_SHIM(const ares_dns_rr_key_t *, ares_dns_rr_get_keys, (ares_dns_rec_type_t type, size_t *cnt), (type, cnt));
IMPL_SHIM(const char *, ares_dns_class_tostr, (ares_dns_class_t qclass), (qclass));
