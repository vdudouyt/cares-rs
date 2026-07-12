/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares-test.h"

// library initialization is only needed for windows builds
#ifdef WIN32
#define EXPECTED_NONINIT ARES_ENOTINITIALIZED
#else
#define EXPECTED_NONINIT ARES_SUCCESS
#endif

namespace ares {
namespace test {

TEST(LibraryInit, Basic) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, UnexpectedCleanup) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, Nested) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, BasicChannelInit) {
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  EXPECT_NE(nullptr, channel);
  ares_destroy(channel);
  ares_library_cleanup();
}

TEST_F(LibraryTest, OptionsChannelInit) {
  struct ares_options opts;
  int optmask = 0;
  memset(&opts, 0, sizeof(opts));
  opts.flags = ARES_FLAG_USEVC | ARES_FLAG_PRIMARY;
  optmask |= ARES_OPT_FLAGS;
  opts.timeout = 2000;
  optmask |= ARES_OPT_TIMEOUTMS;
  opts.tries = 2;
  optmask |= ARES_OPT_TRIES;
  opts.ndots = 4;
  optmask |= ARES_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= ARES_OPT_MAXTIMEOUTMS;
  opts.maxtimeout = 10000;
  optmask |= ARES_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= ARES_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc((size_t)opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= ARES_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc((size_t)opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= ARES_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= ARES_OPT_LOOKUPS;
  optmask |= ARES_OPT_ROTATE;
  opts.resolvconf_path = strdup("/etc/resolv.conf");
  optmask |= ARES_OPT_RESOLVCONF;
  opts.hosts_path = strdup("/etc/hosts");
  optmask |= ARES_OPT_HOSTS_FILE;

  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  ares_channel_t *channel2 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_dup(&channel2, channel));
  EXPECT_NE(nullptr, channel2);

  struct ares_options opts2;
  int optmask2 = 0;
  memset(&opts2, 0, sizeof(opts2));
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel2, &opts2, &optmask2));

  // Note that not all opts-settable fields are saved (e.g.
  // ednspsz, socket_{send,receive}_buffer_size).
  EXPECT_EQ(opts.flags, opts2.flags);
  EXPECT_EQ(opts.timeout, opts2.timeout);
  EXPECT_EQ(opts.tries, opts2.tries);
  EXPECT_EQ(opts.ndots, opts2.ndots);
  EXPECT_EQ(opts.maxtimeout, opts2.maxtimeout);
  EXPECT_EQ(opts.udp_port, opts2.udp_port);
  EXPECT_EQ(opts.tcp_port, opts2.tcp_port);
  EXPECT_EQ(1, opts2.nservers);  // Truncated by ARES_FLAG_PRIMARY
  EXPECT_EQ(opts.servers[0].s_addr, opts2.servers[0].s_addr);
  EXPECT_EQ(opts.ndomains, opts2.ndomains);
  EXPECT_EQ(std::string(opts.domains[0]), std::string(opts2.domains[0]));
  EXPECT_EQ(std::string(opts.domains[1]), std::string(opts2.domains[1]));
  EXPECT_EQ(std::string(opts.lookups), std::string(opts2.lookups));
  EXPECT_EQ(std::string(opts.resolvconf_path), std::string(opts2.resolvconf_path));
  EXPECT_EQ(std::string(opts.hosts_path), std::string(opts2.hosts_path));

  ares_destroy_options(&opts);
  ares_destroy_options(&opts2);
  ares_destroy(channel);
  ares_destroy(channel2);
}

#ifndef WIN32
TEST_F(LibraryTest, EnvInit) {
  ares_channel_t *channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  ares_destroy(channel);
}

// DISABLED: Requires access to channel internals (channel->optmask)
// TEST_F(LibraryTest, EnvInitModernOptions) { ... }
#endif

TEST_F(DefaultChannelTest, SetAddresses) {
  ares_set_local_ip4(channel_, 0x01020304);
  byte addr6[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  ares_set_local_ip6(channel_, addr6);
  ares_set_local_dev(channel_, "dummy");
}

TEST_F(DefaultChannelTest, SetSortlistFailures) {
  EXPECT_EQ(ARES_ENODATA, ares_set_sortlist(nullptr, "1.2.3.4"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "111.111.111.111*/16"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "111.111.111.111/255.255.255.240*"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "1 0123456789012345"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "1 /01234567890123456789012345678901"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "xyzzy ; lwk"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "xyzzy ; 0x123"));
}

TEST_F(DefaultChannelTest, SetSortlistVariants) {
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "1.2.3.4"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "1.2.3.4 ; 2.3.4.5"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "1.2.3.4/26;1234::5678/126;4.5.6.7;5678::1234"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, " 1.2.3.4/26 1234::5678/126   4.5.6.7 5678::1234  "));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "129.1.1.1"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "192.1.1.1"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "224.1.1.1"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "225.1.1.1"));
}

TEST_F(LibraryTest, EnvInitModernOptions) {
  ares_channel_t *channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug retrans:2 ndots:3 attempts:4 timeout:5 rotate");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  // Our ares_save_options always includes ARES_OPT_TIMEOUTMS and ARES_OPT_TRIES
  // in the output mask, so no need to modify channel->optmask directly.
  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel, &opts, &optmask));
  EXPECT_EQ(5000, opts.timeout);
  EXPECT_EQ(4, opts.tries);

  ares_destroy_options(&opts);
  ares_destroy(channel);
}

#ifdef USE_WINSOCK
TEST(Init, NoLibraryInit) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_ENOTINITIALIZED, ares_init(&channel));
}
#endif

}  // namespace test
}  // namespace ares
