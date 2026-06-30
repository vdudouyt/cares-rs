/* Compile-only (-fsyntax-only) sanity check for the cbindgen-generated <cares.h>:
 * proves the header is valid C and that the SUPPORTED API's types, struct field
 * names, and constants match upstream c-ares spellings, so C consumer source
 * compiles against our header unchanged.
 *
 * References only functionality cares-rs actually implements.
 * Built in CI with:  cc -std=c11 -Wall -Wextra -Iinclude -fsyntax-only tests/header_smoke.c
 */
#include <cares.h>
#include <stddef.h>

void cares_rs_header_smoke(void)
{
  /* opaque handle + status type */
  ares_channel_t   *channel = NULL;
  ares_status_t     status  = ARES_SUCCESS;   /* int<-enum-name + #define value */
  (void)channel;
  (void)status;

  /* A / AAAA parse TTL structs (ares_parse_a_reply / ares_parse_aaaa_reply) */
  struct ares_addrttl  a4;
  struct ares_addr6ttl a6;
  (void)a4.ipaddr.s_addr;                     /* upstream: struct in_addr ipaddr  */
  (void)a4.ttl;
  (void)a6.ip6addr._S6_un._S6_u8[0];          /* upstream: struct ares_in6_addr   */
  (void)a6.ttl;

  /* server address node (ares_set_servers / ares_get_servers) */
  struct ares_addr_node node;
  node.next   = NULL;
  node.family = 0;
  (void)node.addr.addr4.s_addr;
  (void)node.addr.addr6._S6_un._S6_u8[15];

  /* reply linked lists expose ->next */
  struct ares_mx_reply   *mx  = NULL;
  struct ares_txt_reply  *txt = NULL;
  struct ares_txt_ext    *txx = NULL;
  struct ares_caa_reply  *caa = NULL;
  struct ares_soa_reply  *soa = NULL;
  struct ares_naptr_reply *nap = NULL;
  struct ares_srv_reply  *srv = NULL;
  struct ares_uri_reply  *uri = NULL;
  if (mx)  mx  = mx->next;
  if (txt) txt = txt->next;
  if (srv) srv = srv->next;
  if (uri) { unsigned short p = uri->priority; (void)p; uri = uri->next; }

  /* Field qualifiers must match upstream (proves residual #2: signedness +
     const). These assignments would warn under -Wpointer-sign /
     -Wdiscarded-qualifiers if our fields were `const char *`. */
  if (txt && txx && caa && soa && nap && mx) {
    unsigned char *u_txt  = txt->txt;          /* unsigned char * */
    unsigned char *u_prop = caa->property;
    unsigned char *u_val  = caa->value;
    unsigned char *u_flag = nap->flags;
    unsigned char  u_rs   = txx->record_start; /* unsigned char   */
    char          *s_host = mx->host;          /* char *           */
    char          *s_ns   = soa->nsname;
    char          *s_repl = nap->replacement;
    (void)u_txt; (void)u_prop; (void)u_val; (void)u_flag; (void)u_rs;
    (void)s_host; (void)s_ns; (void)s_repl;
  }

  /* options struct */
  struct ares_options opts;
  opts.flags   = 0;
  opts.timeout = 0;
  (void)opts;

  /* DNS record manipulation API */
  ares_dns_record_t   *rec = NULL;
  ares_dns_rec_type_t  rt  = (ares_dns_rec_type_t)0;
  (void)rec;
  (void)rt;

  /* getsock helper macros are usable */
  int bits = 0;
  (void)ARES_GETSOCK_READABLE(bits, 0);
  (void)ARES_GETSOCK_MAXNUM;
}
