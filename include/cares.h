#ifndef ARES_H
#define ARES_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <netdb.h>

#define ARES_SUCCESS 0

#define ARES_ENODATA 1

#define ARES_EFORMERR 2

#define ARES_LIB_INIT_ALL 1

typedef struct ares_channeldata ares_channeldata;

typedef struct hostent hostent;

typedef struct ares_channeldata *ares_channel;

typedef void (*ares_host_callback)(void *arg, int status, int timeouts, struct hostent *hostent);

int ares_library_init(int _flags);

int ares_init(ares_channel *out_channel);

void ares_destroy(ares_channel channel);

void ares_gethostbyname(ares_channel channel,
                        const char *hostname,
                        int family,
                        ares_host_callback callback,
                        void *arg);

int ares_fds(ares_channel channel, fd_set *read_fds, fd_set *write_fds);

struct timeval *ares_timeout(ares_channel channel, struct timeval *_maxtv, struct timeval *tv);

void ares_process(ares_channel channel, fd_set *read_fds, fd_set *write_fds);

#endif  /* ARES_H */
