#ifndef ARES__H
#define ARES__H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

/* --- Items cbindgen cannot derive from Rust (injected verbatim) --- */

/* Version (upstream ships these in ares_version.h) */
#define ARES_VERSION_MAJOR 1
#define ARES_VERSION_MINOR 34
#define ARES_VERSION_PATCH 6
#define ARES_VERSION_STR   "1.34.6"
#define ARES_VERSION \
  ((ARES_VERSION_MAJOR << 16) | (ARES_VERSION_MINOR << 8) | (ARES_VERSION_PATCH))

/* ares_getsock() bit helpers: function-like macros have no Rust equivalent.
   ARES_GETSOCK_MAXNUM is emitted by cbindgen and resolved at macro-expansion
   time in consumer code, so definition order does not matter. */
#define ARES_GETSOCK_READABLE(bits, num) ((bits) & (1 << (num)))
#define ARES_GETSOCK_WRITABLE(bits, num) ((bits) & (1 << ((num) + ARES_GETSOCK_MAXNUM)))


#define ARES_SUCCESS 0

#define ARES_ENODATA 1

#define ARES_EFORMERR 2

#define ARES_ESERVFAIL 3

#define ARES_ENOTFOUND 4

#define ARES_ETIMEOUT 12

#define ARES_LIB_INIT_ALL 1

#define RECORD_TYPE_A 1

#define RECORD_TYPE_NS 2

#define RECORD_TYPE_CNAME 5

#define RECORD_TYPE_SOA 6

#define RECORD_TYPE_PTR 12

#define RECORD_TYPE_AAAA 28

#define RECORD_TYPE_MX 15

#define RECORD_TYPE_TXT 16

#define RECORD_TYPE_CAA 257

#define RECORD_TYPE_SRV 33

#define RECORD_TYPE_NAPTR 35

#define RECORD_TYPE_URI 256

#define ARES_AI_CANONNAME (1 << 0)

#define ARES_AI_NUMERICHOST (1 << 1)

#define ARES_AI_PASSIVE (1 << 2)

#define ARES_AI_NUMERICSERV (1 << 3)

#define ARES_AI_V4MAPPED (1 << 4)

#define ARES_AI_ALL (1 << 5)

#define ARES_AI_ADDRCONFIG (1 << 6)

#define ARES_AI_NOSORT (1 << 7)

#define ARES_AI_ENVHOSTS (1 << 8)

#define ARES_NI_NOFQDN (1 << 0)

#define ARES_NI_NUMERICHOST (1 << 1)

#define ARES_NI_NAMEREQD (1 << 2)

#define ARES_NI_NUMERICSERV (1 << 3)

#define ARES_NI_DGRAM (1 << 4)

#define ARES_NI_TCP 0

#define ARES_NI_UDP ARES_NI_DGRAM

#define ARES_NI_SCTP (1 << 5)

#define ARES_NI_DCCP (1 << 6)

#define ARES_NI_NUMERICSCOPE (1 << 7)

#define ARES_NI_LOOKUPHOST (1 << 8)

#define ARES_NI_LOOKUPSERVICE (1 << 9)

#define ARES_GETSOCK_MAXNUM 16

#define ARES_OPT_FLAGS (1 << 0)

#define ARES_OPT_TIMEOUT (1 << 1)

#define ARES_OPT_TRIES (1 << 2)

#define ARES_OPT_NDOTS (1 << 3)

#define ARES_OPT_UDP_PORT (1 << 4)

#define ARES_OPT_TCP_PORT (1 << 5)

#define ARES_OPT_SERVERS (1 << 6)

#define ARES_OPT_DOMAINS (1 << 7)

#define ARES_OPT_LOOKUPS (1 << 8)

#define ARES_OPT_SOCK_STATE_CB (1 << 9)

#define ARES_OPT_SORTLIST (1 << 10)

#define ARES_OPT_SOCK_SNDBUF (1 << 11)

#define ARES_OPT_SOCK_RCVBUF (1 << 12)

#define ARES_OPT_TIMEOUTMS (1 << 13)

#define ARES_OPT_ROTATE (1 << 14)

#define ARES_OPT_EDNSPSZ (1 << 15)

#define ARES_OPT_NOROTATE (1 << 16)

#define ARES_OPT_RESOLVCONF (1 << 17)

#define ARES_OPT_HOSTS_FILE (1 << 18)

#define ARES_OPT_UDP_MAX_QUERIES (1 << 19)

#define ARES_OPT_MAXTIMEOUTMS (1 << 20)

#define ARES_OPT_QUERY_CACHE (1 << 21)

#define ARES_OPT_EVENT_THREAD (1 << 22)

#define ARES_OPT_SERVER_FAILOVER (1 << 23)

#define ARES_TRUE 1

#define ARES_FALSE 0

#define ARES_REC_TYPE_A 1

#define ARES_REC_TYPE_NS 2

#define ARES_REC_TYPE_CNAME 5

#define ARES_REC_TYPE_SOA 6

#define ARES_REC_TYPE_PTR 12

#define ARES_REC_TYPE_HINFO 13

#define ARES_REC_TYPE_MX 15

#define ARES_REC_TYPE_TXT 16

#define ARES_REC_TYPE_AAAA 28

#define ARES_REC_TYPE_SRV 33

#define ARES_REC_TYPE_NAPTR 35

#define ARES_REC_TYPE_OPT 41

#define ARES_REC_TYPE_TLSA 52

#define ARES_REC_TYPE_SVCB 64

#define ARES_REC_TYPE_HTTPS 65

#define ARES_REC_TYPE_ANY 255

#define ARES_REC_TYPE_URI 256

#define ARES_REC_TYPE_CAA 257

#define ARES_REC_TYPE_RAW_RR 65536

#define ARES_CLASS_IN 1

#define ARES_CLASS_CHAOS 3

#define ARES_CLASS_HESOID 4

#define ARES_CLASS_NONE 254

#define ARES_CLASS_ANY 255

#define ARES_SECTION_ANSWER 1

#define ARES_SECTION_AUTHORITY 2

#define ARES_SECTION_ADDITIONAL 3

#define ARES_OPCODE_QUERY 0

#define ARES_OPCODE_IQUERY 1

#define ARES_OPCODE_STATUS 2

#define ARES_OPCODE_NOTIFY 4

#define ARES_OPCODE_UPDATE 5

#define ARES_RCODE_NOERROR 0

#define ARES_RCODE_FORMERR 1

#define ARES_RCODE_SERVFAIL 2

#define ARES_RCODE_NXDOMAIN 3

#define ARES_RCODE_NOTIMP 4

#define ARES_RCODE_REFUSED 5

#define ARES_RCODE_YXDOMAIN 6

#define ARES_RCODE_YXRRSET 7

#define ARES_RCODE_NXRRSET 8

#define ARES_RCODE_NOTAUTH 9

#define ARES_RCODE_NOTZONE 10

#define ARES_RCODE_BADSIG 16

#define ARES_RCODE_BADKEY 17

#define ARES_RCODE_BADTIME 18

#define ARES_RCODE_BADMODE 19

#define ARES_RCODE_BADNAME 20

#define ARES_RCODE_BADALG 21

#define ARES_RCODE_BADTRUNC 22

#define ARES_RCODE_BADCOOKIE 23

#define ARES_DNS_FLAGS_QR (1 << 15)

#define ARES_DNS_FLAGS_AA (1 << 10)

#define ARES_DNS_FLAGS_TC (1 << 9)

#define ARES_DNS_FLAGS_RD (1 << 8)

#define ARES_DNS_FLAGS_RA (1 << 7)

#define ARES_DATATYPE_INADDR 1

#define ARES_DATATYPE_INADDR6 2

#define ARES_DATATYPE_U8 3

#define ARES_DATATYPE_U16 4

#define ARES_DATATYPE_U32 5

#define ARES_DATATYPE_NAME 6

#define ARES_DATATYPE_STR 7

#define ARES_DATATYPE_BIN 8

#define ARES_DATATYPE_BINP 9

#define ARES_DATATYPE_OPT 10

#define ARES_DATATYPE_ABINP 11

#define ARES_RR_A_ADDR (100 + 1)

#define ARES_RR_NS_NSDNAME ((2 * 100) + 1)

#define ARES_RR_CNAME_CNAME ((5 * 100) + 1)

#define ARES_RR_SOA_MNAME ((6 * 100) + 1)

#define ARES_RR_SOA_RNAME ((6 * 100) + 2)

#define ARES_RR_SOA_SERIAL ((6 * 100) + 3)

#define ARES_RR_SOA_REFRESH ((6 * 100) + 4)

#define ARES_RR_SOA_RETRY ((6 * 100) + 5)

#define ARES_RR_SOA_EXPIRE ((6 * 100) + 6)

#define ARES_RR_SOA_MINIMUM ((6 * 100) + 7)

#define ARES_RR_PTR_DNAME ((12 * 100) + 1)

#define ARES_RR_HINFO_CPU ((13 * 100) + 1)

#define ARES_RR_HINFO_OS ((13 * 100) + 2)

#define ARES_RR_MX_PREFERENCE ((15 * 100) + 1)

#define ARES_RR_MX_EXCHANGE ((15 * 100) + 2)

#define ARES_RR_TXT_DATA ((16 * 100) + 1)

#define ARES_RR_AAAA_ADDR ((28 * 100) + 1)

#define ARES_RR_SRV_PRIORITY ((33 * 100) + 2)

#define ARES_RR_SRV_WEIGHT ((33 * 100) + 3)

#define ARES_RR_SRV_PORT ((33 * 100) + 4)

#define ARES_RR_SRV_TARGET ((33 * 100) + 5)

#define ARES_RR_NAPTR_ORDER ((35 * 100) + 1)

#define ARES_RR_NAPTR_PREFERENCE ((35 * 100) + 2)

#define ARES_RR_NAPTR_FLAGS ((35 * 100) + 3)

#define ARES_RR_NAPTR_SERVICES ((35 * 100) + 4)

#define ARES_RR_NAPTR_REGEXP ((35 * 100) + 5)

#define ARES_RR_NAPTR_REPLACEMENT ((35 * 100) + 6)

#define ARES_RR_OPT_UDP_SIZE ((41 * 100) + 1)

#define ARES_RR_OPT_VERSION ((41 * 100) + 3)

#define ARES_RR_OPT_FLAGS ((41 * 100) + 4)

#define ARES_RR_OPT_OPTIONS ((41 * 100) + 5)

#define ARES_RR_TLSA_CERT_USAGE ((52 * 100) + 1)

#define ARES_RR_TLSA_SELECTOR ((52 * 100) + 2)

#define ARES_RR_TLSA_MATCH ((52 * 100) + 3)

#define ARES_RR_TLSA_DATA ((52 * 100) + 4)

#define ARES_RR_SVCB_PRIORITY ((64 * 100) + 1)

#define ARES_RR_SVCB_TARGET ((64 * 100) + 2)

#define ARES_RR_SVCB_PARAMS ((64 * 100) + 3)

#define ARES_RR_HTTPS_PRIORITY ((65 * 100) + 1)

#define ARES_RR_HTTPS_TARGET ((65 * 100) + 2)

#define ARES_RR_HTTPS_PARAMS ((65 * 100) + 3)

#define ARES_RR_URI_PRIORITY ((256 * 100) + 1)

#define ARES_RR_URI_WEIGHT ((256 * 100) + 2)

#define ARES_RR_URI_TARGET ((256 * 100) + 3)

#define ARES_RR_CAA_CRITICAL ((257 * 100) + 1)

#define ARES_RR_CAA_TAG ((257 * 100) + 2)

#define ARES_RR_CAA_VALUE ((257 * 100) + 3)

#define ARES_RR_RAW_RR_TYPE ((65536 * 100) + 1)

#define ARES_RR_RAW_RR_DATA ((65536 * 100) + 2)

#define ARES_ENOTIMP 5

#define ARES_EREFUSED 6

#define ARES_EBADQUERY 7

#define ARES_EBADNAME 8

#define ARES_EBADFAMILY 9

#define ARES_EBADRESP 10

#define ARES_ECONNREFUSED 11

#define ARES_EOF 13

#define ARES_EFILE 14

#define ARES_ENOMEM 15

#define ARES_EDESTRUCTION 16

#define ARES_EBADSTR 17

#define ARES_EBADFLAGS 18

#define ARES_ENONAME 19

#define ARES_EBADHINTS 20

#define ARES_ENOTINITIALIZED 21

#define ARES_ELOADIPHLPAPI 22

#define ARES_EADDRGETNETWORKPARAMS 23

#define ARES_ECANCELLED 24

#define ARES_ESERVICE 25

#define ARES_ENOSERVER 26

typedef struct ares_channeldata ares_channeldata;

typedef struct ares_dns_record_t ares_dns_record_t;

typedef struct ares_dns_rr_t ares_dns_rr_t;

typedef struct ares_channeldata *ares_channel;

typedef void (*ares_host_callback)(void *arg, int status, int timeouts, struct hostent *hostent);

typedef void (*ares_callback)(void *arg, int status, int timeouts, uint8_t *abuf, int alen);

typedef void (*ares_callback_dnsrec)(void *arg,
                                     int status,
                                     size_t timeouts,
                                     struct ares_dns_record_t *dnsrec);

typedef void (*ares_nameinfo_callback)(void *arg,
                                       int status,
                                       int timeouts,
                                       char *node,
                                       char *service);

typedef struct ares_mx_reply {
  struct ares_mx_reply *next;
  const char *host;
  unsigned short priority;
} ares_mx_reply;

typedef struct ares_txt_reply {
  struct ares_txt_reply *next;
  const char *txt;
  size_t length;
} ares_txt_reply;

typedef struct ares_txt_ext {
  struct ares_txt_ext *next;
  const char *txt;
  size_t length;
  char record_start;
} ares_txt_ext;

typedef struct ares_caa_reply {
  struct ares_caa_reply *next;
  int critical;
  const char *property;
  size_t plength;
  const char *value;
  size_t length;
} ares_caa_reply;

typedef struct ares_naptr_reply {
  struct ares_naptr_reply *next;
  const char *flags;
  const char *service;
  const char *regexp;
  const char *replacement;
  uint16_t order;
  uint16_t preference;
} ares_naptr_reply;

typedef struct ares_srv_reply {
  struct ares_srv_reply *next;
  const char *host;
  unsigned short priority;
  unsigned short weight;
  unsigned short port;
} ares_srv_reply;

typedef struct ares_uri_reply {
  struct ares_uri_reply *next;
  unsigned short priority;
  unsigned short weight;
  const char *uri;
  int ttl;
} ares_uri_reply;

typedef struct ares_addrttl {
  struct in_addr ipaddr;
  int ttl;
} ares_addrttl;

typedef struct ares_in6_addr_un {
  uint8_t _S6_u8[16];
} ares_in6_addr_un;

typedef struct ares_in6_addr {
  struct ares_in6_addr_un _S6_un;
} ares_in6_addr;

typedef struct ares_addr6ttl {
  struct ares_in6_addr ip6addr;
  int ttl;
} ares_addr6ttl;

typedef struct ares_soa_reply {
  const char *nsname;
  const char *hostmaster;
  unsigned int serial;
  unsigned int refresh;
  unsigned int retry;
  unsigned int expire;
  unsigned int minttl;
} ares_soa_reply;

typedef union ares_addr_union {
  struct in_addr addr4;
  struct ares_in6_addr addr6;
} ares_addr_union;

typedef struct ares_addr_node {
  struct ares_addr_node *next;
  int family;
  union ares_addr_union addr;
} ares_addr_node;

typedef struct ares_addr_port_node {
  struct ares_addr_port_node *next;
  int family;
  union ares_addr_union addr;
  int udp_port;
  int tcp_port;
} ares_addr_port_node;

typedef int ares_socket_t;

typedef int (*ares_sock_create_callback)(int socket_fd, int sock_type, void *arg);

typedef struct ares_addrinfo_hints {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
} ares_addrinfo_hints;

typedef struct ares_addrinfo_cname {
  int ttl;
  char *alias;
  char *name;
  struct ares_addrinfo_cname *next;
} ares_addrinfo_cname;

typedef struct ares_addrinfo_node {
  int ai_ttl;
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  socklen_t ai_addrlen;
  struct sockaddr *ai_addr;
  struct ares_addrinfo_node *ai_next;
} ares_addrinfo_node;

typedef struct ares_addrinfo {
  struct ares_addrinfo_cname *cnames;
  struct ares_addrinfo_node *nodes;
  char *name;
} ares_addrinfo;

typedef void (*ares_addrinfo_callback)(void *arg,
                                       int status,
                                       int timeouts,
                                       struct ares_addrinfo *res);

typedef int (*ares_sock_config_callback)(int socket_fd, int sock_type, void *arg);

typedef void (*ares_server_state_callback)(const char *server_string,
                                           int success,
                                           int flags,
                                           void *arg);

typedef void (*ares_sock_state_cb)(void *data, ares_socket_t socket_fd, int readable, int writable);

typedef struct apattern {
  uint8_t _private[0];
} apattern;

typedef int ares_evsys_t;

typedef struct ares_server_failover_options {
  unsigned short retry_chance;
  size_t retry_delay;
} ares_server_failover_options;

typedef struct ares_options {
  int flags;
  int timeout;
  int tries;
  int ndots;
  unsigned short udp_port;
  unsigned short tcp_port;
  int socket_send_buffer_size;
  int socket_receive_buffer_size;
  struct in_addr *servers;
  int nservers;
  char **domains;
  int ndomains;
  char *lookups;
  ares_sock_state_cb sock_state_cb;
  void *sock_state_cb_data;
  struct apattern *sortlist;
  int nsort;
  int ednspsz;
  char *resolvconf_path;
  char *hosts_path;
  int udp_max_queries;
  int maxtimeout;
  unsigned int qcache_max_ttl;
  ares_evsys_t evsys;
  struct ares_server_failover_options server_failover_opts;
} ares_options;

typedef ssize_t ares_ssize_t;

typedef struct ares_socket_functions {
  ares_socket_t (*asocket)(int domain, int, int, void *user_data);
  int (*aclose)(ares_socket_t fd, void *user_data);
  int (*aconnect)(ares_socket_t fd, const struct sockaddr*, socklen_t, void *user_data);
  ares_ssize_t (*arecvfrom)(ares_socket_t fd,
                            void*,
                            size_t,
                            int,
                            struct sockaddr*,
                            socklen_t*,
                            void *user_data);
  ares_ssize_t (*asendv)(ares_socket_t fd, const struct iovec*, int, void *user_data);
} ares_socket_functions;

typedef struct ares_socket_functions_ex {
  unsigned int version;
  unsigned int flags;
  ares_socket_t (*asocket)(int, int, int, void*);
  int (*aclose)(ares_socket_t, void*);
  int (*asetsockopt)(ares_socket_t, int, const void*, socklen_t, void*);
  int (*aconnect)(ares_socket_t, const struct sockaddr*, socklen_t, unsigned int, void*);
  ares_ssize_t (*arecvfrom)(ares_socket_t, void*, size_t, int, struct sockaddr*, socklen_t*, void*);
  ares_ssize_t (*asendto)(ares_socket_t,
                          const void*,
                          size_t,
                          int,
                          const struct sockaddr*,
                          socklen_t,
                          void*);
} ares_socket_functions_ex;

typedef int ares_status_t;

typedef int ares_bool_t;

typedef socklen_t ares_socklen_t;

typedef unsigned int ares_dns_rec_type_t;

typedef unsigned int ares_dns_class_t;

typedef unsigned int ares_dns_section_t;

typedef unsigned int ares_dns_opcode_t;

typedef unsigned int ares_dns_rcode_t;

typedef unsigned int ares_dns_flags_t;

typedef unsigned int ares_dns_datatype_t;

typedef unsigned int ares_dns_rr_key_t;

#define ARES_SOCKET_BAD -1

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int ares_library_init(int _flags);

void ares_library_cleanup(void);

int32_t ares_threadsafety(void);

int ares_init(ares_channel *out_channel);

int ares_dup(ares_channel *dest, ares_channel source);

void ares_cancel(ares_channel channel);

void ares_destroy(ares_channel channel);

void ares_gethostbyname(ares_channel channel,
                        const char *hostname,
                        int family,
                        ares_host_callback callback,
                        void *arg);

int ares_gethostbyname_file(struct ares_channeldata *channel,
                            const char *name,
                            int family,
                            struct hostent **host);

void ares_gethostbyaddr(ares_channel channel,
                        void *addr,
                        int addrlen,
                        int family,
                        ares_host_callback callback,
                        void *arg);

void ares_search(ares_channel channel,
                 const char *name,
                 int dnsclass,
                 int dnstype,
                 ares_callback callback,
                 void *arg);

void ares_query(ares_channel channel,
                const char *name,
                int _dnsclass,
                int dnstype,
                ares_callback callback,
                void *arg);

void ares_query_dnsrec(ares_channel channel,
                       const char *name,
                       int _dnsclass,
                       int dnstype,
                       ares_callback_dnsrec callback,
                       void *arg,
                       int *_qid);

void ares_search_dnsrec(ares_channel channel,
                        struct ares_dns_record_t *dnsrec,
                        ares_callback_dnsrec callback,
                        void *arg);

void ares_getnameinfo(ares_channel channel,
                      const struct sockaddr *sa,
                      socklen_t salen,
                      int flags,
                      ares_nameinfo_callback callback,
                      void *arg);

int ares_parse_mx_reply(const uint8_t *abuf, int alen, struct ares_mx_reply **out);

int ares_parse_txt_reply(const uint8_t *abuf, int alen, struct ares_txt_reply **out);

int ares_parse_txt_reply_ext(const uint8_t *abuf, int alen, struct ares_txt_ext **out);

int ares_parse_caa_reply(const uint8_t *abuf, int alen, struct ares_caa_reply **out);

int ares_parse_naptr_reply(const uint8_t *abuf, int alen, struct ares_naptr_reply **out);

int ares_parse_srv_reply(const uint8_t *abuf, int alen, struct ares_srv_reply **out);

int ares_parse_uri_reply(const uint8_t *abuf, int alen, struct ares_uri_reply **out);

int ares_parse_ns_reply(const uint8_t *abuf, int alen, struct hostent **out);

int ares_parse_a_reply(const uint8_t *abuf,
                       int alen,
                       struct hostent **out,
                       struct ares_addrttl *addrttls,
                       int *out_naddrttls);

int ares_parse_aaaa_reply(const uint8_t *abuf,
                          int alen,
                          struct hostent **out,
                          struct ares_addr6ttl *addrttls,
                          int *out_naddrttls);

int ares_parse_ptr_reply(const uint8_t *abuf,
                         int alen,
                         const void *addr,
                         int addrlen,
                         int family,
                         struct hostent **out);

int ares_parse_soa_reply(const uint8_t *abuf, int alen, struct ares_soa_reply **out);

void ares_free_hostent(struct hostent *hostent);

int ares_fds(ares_channel channel, fd_set *read_fds, fd_set *write_fds);

struct timeval *ares_timeout(ares_channel channel, struct timeval *maxtv, struct timeval *tv);

void ares_process_fd(ares_channel channel, int read_fd, int write_fd);

void ares_process(ares_channel channel, fd_set *read_fds, fd_set *write_fds);

int ares_set_servers(ares_channel channel, struct ares_addr_node *head);

int ares_set_servers_ports(ares_channel channel, struct ares_addr_port_node *head);

int ares_get_servers_ports(ares_channel channel, struct ares_addr_port_node **out);

int ares_set_servers_ports_csv(ares_channel channel, const char *servers);

int ares_set_servers_csv(ares_channel channel, const char *servers);

const char *ares_version(int *version);

int ares_getsock(ares_channel channel, ares_socket_t *socks, int numsocks);

void ares_free_string(void *s);

void ares_set_local_ip4(ares_channel _channel, uint32_t _local_ip);

void ares_set_local_ip6(ares_channel _channel, const uint8_t *_local_ip6);

void ares_set_local_dev(ares_channel _channel, const char *_local_dev_name);

void ares_set_socket_callback(ares_channel channel, ares_sock_create_callback callback, void *arg);

int ares_inet_pton(int af, const char *src, void *dst);

int ares_expand_name(const uint8_t *encoded, const uint8_t *abuf, int alen, char **s, long *enclen);

void ares_getaddrinfo(ares_channel channel,
                      const char *name,
                      const char *service,
                      const struct ares_addrinfo_hints *hints,
                      ares_addrinfo_callback callback,
                      void *arg);

void ares_freeaddrinfo(struct ares_addrinfo *ai);

int ares_library_initialized(void);

const char *ares_inet_ntop(int af, const void *src, char *dst, socklen_t size);

int ares_get_servers(ares_channel channel, struct ares_addr_node **out);

char *ares_get_servers_csv(ares_channel channel);

int ares_expand_string(const uint8_t *encoded,
                       const uint8_t *abuf,
                       int alen,
                       uint8_t **s,
                       long *enclen);

int ares_create_query(const char *name,
                      int dnsclass,
                      int qtype,
                      int id,
                      int rd,
                      uint8_t **buf,
                      int *buflen,
                      int max_udp_size);

int ares_mkquery(const char *name,
                 int dnsclass,
                 int qtype,
                 int id,
                 int rd,
                 uint8_t **buf,
                 int *buflen);

void ares_send(ares_channel channel,
               const uint8_t *qbuf,
               int qlen,
               ares_callback callback,
               void *arg);

int ares_set_sortlist(ares_channel channel, const char *sortstr);

int ares_reinit(ares_channel channel);

void ares_set_socket_configure_callback(ares_channel channel,
                                        ares_sock_config_callback callback,
                                        void *arg);

void ares_set_server_state_callback(ares_channel channel,
                                    ares_server_state_callback callback,
                                    void *arg);

int ares_queue_active_queries(ares_channel channel);

int ares_queue_wait_empty(ares_channel _channel, int _timeout_ms);

void ares_free_data(void *dataptr);

int ares_init_options(ares_channel *out_channel, const struct ares_options *options, int optmask);

int ares_save_options(ares_channel channel, struct ares_options *options, int *optmask);

void ares_destroy_options(struct ares_options *options);

void ares_set_socket_functions(ares_channel channel,
                               const struct ares_socket_functions *funcs,
                               void *user_data);

int ares_set_socket_functions_ex(ares_channel channel,
                                 const struct ares_socket_functions_ex *funcs,
                                 void *user_data);

int ares_dns_record_create(struct ares_dns_record_t **dnsrec,
                           unsigned int id,
                           unsigned int flags,
                           unsigned int opcode,
                           unsigned int rcode);

void ares_dns_record_destroy(struct ares_dns_record_t *dnsrec);

struct ares_dns_record_t *ares_dns_record_duplicate(const struct ares_dns_record_t *dnsrec);

unsigned int ares_dns_record_get_id(const struct ares_dns_record_t *dnsrec);

unsigned int ares_dns_record_get_flags(const struct ares_dns_record_t *dnsrec);

unsigned int ares_dns_record_get_opcode(const struct ares_dns_record_t *dnsrec);

unsigned int ares_dns_record_get_rcode(const struct ares_dns_record_t *dnsrec);

void ares_dns_record_set_id(struct ares_dns_record_t *dnsrec, unsigned int id);

int ares_dns_record_query_add(struct ares_dns_record_t *dnsrec,
                              const char *name,
                              unsigned int qtype,
                              unsigned int qclass);

size_t ares_dns_record_query_cnt(const struct ares_dns_record_t *dnsrec);

int ares_dns_record_query_get(const struct ares_dns_record_t *dnsrec,
                              size_t idx,
                              const char **name,
                              unsigned int *qtype,
                              unsigned int *qclass);

int ares_dns_record_query_set_name(struct ares_dns_record_t *dnsrec, size_t idx, const char *name);

int ares_dns_record_query_set_type(struct ares_dns_record_t *dnsrec,
                                   size_t idx,
                                   unsigned int qtype);

int ares_dns_record_rr_add(struct ares_dns_rr_t **rr,
                           struct ares_dns_record_t *dnsrec,
                           unsigned int sect,
                           const char *name,
                           unsigned int rtype,
                           unsigned int rclass,
                           unsigned int ttl);

size_t ares_dns_record_rr_cnt(const struct ares_dns_record_t *dnsrec, unsigned int sect);

struct ares_dns_rr_t *ares_dns_record_rr_get(struct ares_dns_record_t *dnsrec,
                                             unsigned int sect,
                                             size_t idx);

const struct ares_dns_rr_t *ares_dns_record_rr_get_const(const struct ares_dns_record_t *dnsrec,
                                                         unsigned int sect,
                                                         size_t idx);

int ares_dns_record_rr_del(struct ares_dns_record_t *dnsrec, unsigned int sect, size_t idx);

const char *ares_dns_rr_get_name(const struct ares_dns_rr_t *rr);

unsigned int ares_dns_rr_get_type(const struct ares_dns_rr_t *rr);

unsigned int ares_dns_rr_get_class(const struct ares_dns_rr_t *rr);

unsigned int ares_dns_rr_get_ttl(const struct ares_dns_rr_t *rr);

const struct in_addr *ares_dns_rr_get_addr(const struct ares_dns_rr_t *rr, unsigned int key);

const struct ares_in6_addr *ares_dns_rr_get_addr6(const struct ares_dns_rr_t *rr, unsigned int key);

const char *ares_dns_rr_get_str(const struct ares_dns_rr_t *rr, unsigned int key);

uint8_t ares_dns_rr_get_u8(const struct ares_dns_rr_t *rr, unsigned int key);

uint16_t ares_dns_rr_get_u16(const struct ares_dns_rr_t *rr, unsigned int key);

uint32_t ares_dns_rr_get_u32(const struct ares_dns_rr_t *rr, unsigned int key);

const uint8_t *ares_dns_rr_get_bin(const struct ares_dns_rr_t *rr, unsigned int key, size_t *len);

int ares_dns_rr_set_addr(struct ares_dns_rr_t *rr, unsigned int key, const struct in_addr *addr);

int ares_dns_rr_set_addr6(struct ares_dns_rr_t *rr,
                          unsigned int key,
                          const struct ares_in6_addr *addr);

int ares_dns_rr_set_str(struct ares_dns_rr_t *rr, unsigned int key, const char *val);

int ares_dns_rr_set_u8(struct ares_dns_rr_t *rr, unsigned int key, uint8_t val);

int ares_dns_rr_set_u16(struct ares_dns_rr_t *rr, unsigned int key, uint16_t val);

int ares_dns_rr_set_u32(struct ares_dns_rr_t *rr, unsigned int key, uint32_t val);

int ares_dns_rr_set_bin(struct ares_dns_rr_t *rr, unsigned int key, const uint8_t *val, size_t len);

int ares_dns_rr_set_opt(struct ares_dns_rr_t *rr,
                        unsigned int key,
                        unsigned int opt,
                        const uint8_t *val,
                        size_t val_len);

size_t ares_dns_rr_get_opt_cnt(const struct ares_dns_rr_t *rr, unsigned int key);

int ares_dns_rr_get_opt(const struct ares_dns_rr_t *rr,
                        unsigned int key,
                        size_t idx,
                        unsigned int *opt,
                        const uint8_t **val,
                        size_t *val_len);

int ares_dns_rr_get_opt_byid(const struct ares_dns_rr_t *rr,
                             unsigned int key,
                             unsigned int opt,
                             const uint8_t **val,
                             size_t *val_len);

int ares_dns_rr_del_opt_byid(struct ares_dns_rr_t *rr, unsigned int key, unsigned int opt);

int ares_dns_parse(const uint8_t *buf,
                   size_t buf_len,
                   unsigned int flags,
                   struct ares_dns_record_t **dnsrec);

int ares_dns_write(const struct ares_dns_record_t *dnsrec, uint8_t **buf, size_t *buf_len);

const char *ares_dns_rec_type_tostr(unsigned int rtype);

int ares_dns_rec_type_fromstr(unsigned int *rtype, const char *str_ptr);

const char *ares_dns_class_tostr(unsigned int qclass);

int ares_dns_class_fromstr(const char *str_ptr, unsigned int *qclass);

const char *ares_dns_rr_key_tostr(unsigned int key);

const unsigned int *ares_dns_rr_get_keys(unsigned int rtype, size_t *cnt);

unsigned int ares_dns_rr_key_datatype(unsigned int key);

unsigned int ares_dns_rr_key_to_rec_type(unsigned int key);

const char *ares_dns_opcode_tostr(unsigned int opcode);

const char *ares_dns_rcode_tostr(unsigned int rcode);

const char *ares_dns_section_tostr(unsigned int section);

size_t ares_dns_rr_get_abin_cnt(const struct ares_dns_rr_t *rr, unsigned int key);

const uint8_t *ares_dns_rr_get_abin(const struct ares_dns_rr_t *rr,
                                    unsigned int key,
                                    size_t idx,
                                    size_t *len);

void ares_free(void *ptr);

const char *ares_strerror(int code);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* ARES__H */


/* Modern channel handle typedef (upstream ares.h). cbindgen already emits the
   opaque `struct ares_channeldata` and the legacy `ares_channel` pointer typedef. */
typedef struct ares_channeldata ares_channel_t;
