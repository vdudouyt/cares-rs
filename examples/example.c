#include <stdio.h>
#include <arpa/inet.h>
#include <cares.h>

// build: gcc example.c -lcares_rs -o example
// $ ./example google.com
// Resolved: 142.250.179.206

static void callback(void *arg, int status, int timeouts, struct hostent *host) {
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "Failed\n");
        return;
    }

    char ip[INET6_ADDRSTRLEN];
    for (int i = 0; host->h_addr_list[i]; i++) {
        inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
        printf("Resolved: %s\n", ip);
    }
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "Wrong usage\n");
        exit(-1);
    }
    ares_channel channel;
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        fprintf(stderr, "Failed to init c-ares\n");
        return 1;
    }

    if (ares_init(&channel) != ARES_SUCCESS) {
        fprintf(stderr, "Failed to init channel\n");
        return 1;
    }

    ares_gethostbyname(channel, argv[1], AF_INET, callback, NULL);

    for (;;) {
      fd_set readers, writers;
      int nfds = ares_fds(channel, &readers, &writers);
      if(nfds == 0) break;  // no more queries

      struct timeval tv_buf;
      struct timeval *tv = ares_timeout(channel, NULL, &tv_buf);

      select(nfds, &readers, &writers, NULL, tv);
      ares_process(channel, &readers, &writers);
    }
    ares_destroy(channel);
}
