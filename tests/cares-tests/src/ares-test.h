/* Adapted from c-ares test suite for cares-rs */
#ifndef ARES_TEST_H
#define ARES_TEST_H

#include "dns-proto.h"
#include "ares_dns.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>
#include <chrono>
#include <sstream>

#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define sclose(x) close(x)

#include "loader.h"

namespace ares {
namespace test {

extern bool                                    verbose;
extern unsigned short                          mock_port;
extern const std::vector<int>                  both_families;
extern const std::vector<int>                  ipv4_family;
extern const std::vector<int>                  ipv6_family;

extern const std::vector<std::pair<int, bool>> both_families_both_modes;
extern const std::vector<std::pair<int, bool>> ipv4_family_both_modes;
extern const std::vector<std::pair<int, bool>> ipv6_family_both_modes;

// Which parameters to use in tests
extern std::vector<int>                  families;
extern std::vector<std::pair<int, bool>> families_modes;

// Hopefully a more accurate sleep than sleep_for()
void                    ares_sleep_time(unsigned int ms);

// Process all pending work on ares-owned file descriptors, plus
// optionally the given set-of-FDs + work function.
void                    ProcessWork(ares_channel_t                          *channel,
                                    std::function<std::set<ares_socket_t>()> get_extrafds,
                                    std::function<void(ares_socket_t)>       process_extra,
                                    unsigned int                             cancel_ms = 0);
std::set<ares_socket_t> NoExtraFDs();

const char             *af_tostr(int af);
const char             *mode_tostr(bool mode);
std::string
  PrintFamilyMode(const testing::TestParamInfo<std::pair<int, bool>> &info);
std::string PrintFamily(const testing::TestParamInfo<int> &info);

// Test fixture that ensures library initialization.
class LibraryTest : public ::testing::Test {
public:
  LibraryTest()
  {
    EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  }

  ~LibraryTest()
  {
    ares_library_cleanup();
    ClearFails();
  }

  // Alloc failure injection stubs (not functional for cares-rs, but needed for API compat)
  static void  SetAllocFail(int nth);
  static void  SetAllocSizeFail(size_t size);
  static void  ClearFails();

  static void SetFailSend(void);
  static ares_ssize_t ares_sendv_fail(ares_socket_t socket, const struct iovec *vec, int len,
                                      void *user_data);

private:
  static unsigned long long    fails_;
  static std::map<size_t, int> size_fails_;
  static std::mutex            lock_;
  static bool                  failsend_;
};

// Test fixture that uses a default channel.
class DefaultChannelTest : public LibraryTest {
public:
  DefaultChannelTest() : channel_(nullptr)
  {
    /* Enable query cache for live tests */
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.qcache_max_ttl = 300;
    int optmask         = ARES_OPT_QUERY_CACHE;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
  }

  ~DefaultChannelTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Test fixture that uses a file-only channel.
class FileChannelTest : public LibraryTest {
public:
  FileChannelTest() : channel_(nullptr)
  {
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.lookups = strdup("f");
    int optmask  = ARES_OPT_LOOKUPS;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
    free(opts.lookups);
  }

  ~FileChannelTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Test fixture that uses a default channel with the specified lookup mode.
class DefaultChannelModeTest
  : public LibraryTest,
    public ::testing::WithParamInterface<std::string> {
public:
  DefaultChannelModeTest() : channel_(nullptr)
  {
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.lookups = strdup(GetParam().c_str());
    int optmask  = ARES_OPT_LOOKUPS;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
    free(opts.lookups);
  }

  ~DefaultChannelModeTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Mock DNS server to allow responses to be scripted by tests.
class MockServer {
public:
  MockServer(int family, unsigned short port);
  ~MockServer();

  // Mock method indicating the processing of a particular <name, RRtype> request.
  MOCK_METHOD2(OnRequest, void(const std::string &name, int rrtype));

  void SetReplyData(const std::vector<byte> &reply)
  {
    exact_reply_ = reply;
    reply_       = nullptr;
  }

  void SetReply(const DNSPacket *reply)
  {
    reply_ = reply;
    exact_reply_.clear();
  }

  void SetReplyExpRequest(const DNSPacket *reply, const std::string &request)
  {
    expected_request_ = request;
    reply_            = reply;
  }

  void SetReplyQID(int qid)
  {
    qid_ = qid;
  }

  void Disconnect()
  {
    reply_ = nullptr;
    exact_reply_.clear();
    for (ares_socket_t fd : connfds_) {
      sclose(fd);
    }
    connfds_.clear();
    free(tcp_data_);
    tcp_data_     = NULL;
    tcp_data_len_ = 0;
  }

  std::set<ares_socket_t> fds() const;
  void                    ProcessFD(ares_socket_t fd);

  unsigned short          udpport() const
  {
    return udpport_;
  }

  unsigned short tcpport() const
  {
    return tcpport_;
  }

private:
  void           ProcessRequest(ares_socket_t fd, struct sockaddr_storage *addr,
                                ares_socklen_t addrlen, const std::vector<byte> &req,
                                const std::string &reqstr, int qid, const char *name,
                                int rrtype);
  void           ProcessPacket(ares_socket_t fd, struct sockaddr_storage *addr,
                               ares_socklen_t addrlen, byte *data, int len);
  unsigned short udpport_;
  unsigned short tcpport_;
  ares_socket_t  udpfd_;
  ares_socket_t  tcpfd_;
  std::set<ares_socket_t> connfds_;
  std::vector<byte>       exact_reply_;
  const DNSPacket        *reply_;
  std::string             expected_request_;
  int                     qid_;
  unsigned char          *tcp_data_;
  size_t                  tcp_data_len_;
};

// Test fixture that uses a mock DNS server.
class MockChannelOptsTest : public LibraryTest {
public:
  MockChannelOptsTest(int count, int family, bool force_tcp,
                      bool honor_sysconfig, struct ares_options *givenopts,
                      int optmask);
  ~MockChannelOptsTest();

  void ProcessAltChannel(ares_channel_t *chan, unsigned int cancel_ms = 0);
  void Process(unsigned int cancel_ms = 0);

protected:
  typedef testing::NiceMock<MockServer>                NiceMockServer;
  typedef std::vector<std::unique_ptr<NiceMockServer>> NiceMockServers;

  std::set<ares_socket_t>                              fds() const;
  void                   ProcessFD(ares_socket_t fd);

  static NiceMockServers BuildServers(int count, int family,
                                      unsigned short base_port);

  NiceMockServers        servers_;
  NiceMockServer        &server_;
  ares_channel_t        *channel_;
};

class MockChannelTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockChannelTest()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, false,
                          nullptr, 0)
  {
  }
};

class MockUDPChannelTest : public MockChannelOptsTest,
                           public ::testing::WithParamInterface<int> {
public:
  MockUDPChannelTest()
    : MockChannelOptsTest(1, GetParam(), false, false, nullptr, 0)
  {
  }
};

class MockTCPChannelTest : public MockChannelOptsTest,
                           public ::testing::WithParamInterface<int> {
public:
  MockTCPChannelTest()
    : MockChannelOptsTest(1, GetParam(), true, false, nullptr, 0)
  {
  }
};

class MockFlagsChannelOptsTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockFlagsChannelOptsTest(int flags)
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, false,
                          FillOptions(&opts_, flags), ARES_OPT_FLAGS) {}
  static struct ares_options* FillOptions(struct ares_options *opts, int flags) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->flags = flags;
    return opts;
  }
private:
  struct ares_options opts_;
};

class MockNoCheckRespChannelTest : public MockFlagsChannelOptsTest {
public:
  MockNoCheckRespChannelTest() : MockFlagsChannelOptsTest(ARES_FLAG_NOCHECKRESP) {}
};

class MockExtraOptsTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockExtraOptsTest()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, false,
                          FillOptions(&opts_),
                          ARES_OPT_SOCK_SNDBUF|ARES_OPT_SOCK_RCVBUF) {}
  static struct ares_options* FillOptions(struct ares_options *opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->socket_send_buffer_size = 514;
    opts->socket_receive_buffer_size = 514;
    return opts;
  }
private:
  struct ares_options opts_;
};

class MockMultiServerChannelTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockMultiServerChannelTest(ares_options *opts, int optmask)
    : MockChannelOptsTest(3, GetParam().first, GetParam().second, false, opts, optmask) {}
  void CheckExample();
};

class NoRotateMultiMockTest : public MockMultiServerChannelTest {
public:
  NoRotateMultiMockTest() : MockMultiServerChannelTest(nullptr, ARES_OPT_NOROTATE) {}
};

#define MAXUDPQUERIES_TOTAL 32
#define MAXUDPQUERIES_LIMIT 8

class MockUDPMaxQueriesTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<int> {
public:
  MockUDPMaxQueriesTest()
    : MockChannelOptsTest(1, GetParam(), false, false,
                          FillOptions(&opts_),
                          ARES_OPT_UDP_MAX_QUERIES) {}
  static struct ares_options* FillOptions(struct ares_options *opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->udp_max_queries = MAXUDPQUERIES_LIMIT;
    return opts;
  }
private:
  struct ares_options opts_;
};

class CacheQueriesTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<int> {
public:
  CacheQueriesTest()
    : MockChannelOptsTest(1, GetParam(), false, false,
                          FillOptions(&opts_),
                          ARES_OPT_QUERY_CACHE) {}
  static struct ares_options* FillOptions(struct ares_options *opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->qcache_max_ttl = 3600;
    return opts;
  }
private:
  struct ares_options opts_;
};

#define SERVER_FAILOVER_RETRY_DELAY 30

class ServerFailoverOptsMultiMockTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  ServerFailoverOptsMultiMockTest()
    : MockChannelOptsTest(4, GetParam().first, GetParam().second, false,
                          FillOptions(&opts_),
                          ARES_OPT_SERVER_FAILOVER | ARES_OPT_NOROTATE) {}
  void CheckExample();
  static struct ares_options* FillOptions(struct ares_options *opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->server_failover_opts.retry_chance = 1;
    opts->server_failover_opts.retry_delay = SERVER_FAILOVER_RETRY_DELAY;
    return opts;
  }
private:
  struct ares_options opts_;
};

// gMock actions
ACTION_P2(SetReplyData, mockserver, data)
{
  mockserver->SetReplyData(data);
}

ACTION_P2(SetReply, mockserver, reply)
{
  mockserver->SetReply(reply);
}

ACTION_P3(SetReplyExpRequest, mockserver, reply, request)
{
  mockserver->SetReplyExpRequest(reply, request);
}

ACTION_P2(SetReplyQID, mockserver, qid)
{
  mockserver->SetReplyQID(qid);
}

ACTION_P2(SetReplyAndFailSend, mockserver, reply)
{
  mockserver->SetReply(reply);
  LibraryTest::SetFailSend();
}

ACTION_P2(CancelChannel, mockserver, channel)
{
  ares_cancel(channel);
}

ACTION_P(Disconnect, mockserver)
{
  mockserver->Disconnect();
}

// C++ wrapper for struct hostent.
struct HostEnt {
  HostEnt() : addrtype_(-1)
  {
  }

  HostEnt(const struct hostent *hostent);
  std::string              name_;
  std::vector<std::string> aliases_;
  int                      addrtype_;
  std::vector<std::string> addrs_;
};

std::ostream &operator<<(std::ostream &os, const HostEnt &result);

// Structure that describes the result of an ares_host_callback invocation.
struct HostResult {
  HostResult() : done_(false), status_(0), timeouts_(0)
  {
  }

  bool    done_;
  int     status_;
  int     timeouts_;
  HostEnt host_;
};

std::ostream &operator<<(std::ostream &os, const HostResult &result);

// C++ wrapper for ares_dns_record_t.
struct AresDnsRecord {
  ~AresDnsRecord()
  {
    ares_dns_record_destroy(dnsrec_);
    dnsrec_ = NULL;
  }

  AresDnsRecord() : dnsrec_(NULL)
  {
  }

  void SetDnsRecord(const ares_dns_record_t *dnsrec)
  {
    if (dnsrec_ != NULL) {
      ares_dns_record_destroy(dnsrec_);
    }
    if (dnsrec == NULL) {
      return;
    }
    dnsrec_ = ares_dns_record_duplicate(dnsrec);
  }

  ares_dns_record_t *dnsrec_ = NULL;
};

// Structure that describes the result of an ares_callback_dnsrec invocation.
struct QueryResult {
  QueryResult() : done_(false), status_(ARES_SUCCESS), timeouts_(0)
  {
  }

  bool          done_;
  ares_status_t status_;
  size_t        timeouts_;
  AresDnsRecord dnsrec_;
};

std::ostream &operator<<(std::ostream &os, const QueryResult &result);

// Structure that describes the result of an ares_callback invocation.
struct SearchResult {
  bool              done_;
  int               status_;
  int               timeouts_;
  std::vector<byte> data_;
};

std::ostream &operator<<(std::ostream &os, const SearchResult &result);

struct NameInfoResult {
  bool        done_;
  int         status_;
  int         timeouts_;
  std::string node_;
  std::string service_;
};

std::ostream &operator<<(std::ostream &os, const NameInfoResult &result);

struct AddrInfoDeleter {
  void operator()(ares_addrinfo *ptr)
  {
    if (ptr) {
      ares_freeaddrinfo(ptr);
    }
  }
};

using AddrInfo = std::unique_ptr<ares_addrinfo, AddrInfoDeleter>;

std::ostream &operator<<(std::ostream &os, const AddrInfo &result);

struct AddrInfoResult {
  AddrInfoResult() : done_(false), status_(-1), timeouts_(0)
  {
  }

  bool     done_;
  int      status_;
  int      timeouts_;
  AddrInfo ai_;
};

std::ostream &operator<<(std::ostream &os, const AddrInfoResult &result);

// Standard callbacks
void          HostCallback(void *data, int status, int timeouts,
                           struct hostent *hostent);
void SearchCallback(void *data, int status, int timeouts, unsigned char *abuf,
                    int alen);
void QueryCallback(void *data, ares_status_t status, size_t timeouts,
                   const ares_dns_record_t *dnsrec);
void SearchCallbackDnsRec(void *data, ares_status_t status, size_t timeouts,
                          const ares_dns_record_t *dnsrec);
void NameInfoCallback(void *data, int status, int timeouts, char *node,
                      char *service);
void AddrInfoCallback(void *data, int status, int timeouts,
                      struct ares_addrinfo *res);

// Out-of-line definitions for methods that depend on HostResult/HostCallback
inline void MockMultiServerChannelTest::CheckExample() {
  HostResult result;
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

inline void ServerFailoverOptsMultiMockTest::CheckExample() {
  HostResult result;
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

// Retrieve the name servers used by a channel.
std::string GetNameServers(ares_channel_t *channel);

// RAII class to temporarily create a directory of a given name.
class TransientDir {
public:
  TransientDir(const std::string &dirname);
  ~TransientDir();

private:
  std::string dirname_;
};

// C++ wrapper around tempnam()
std::string TempNam(const char *dir, const char *prefix);

// RAII class to temporarily create file of a given name and contents.
class TransientFile {
public:
  TransientFile(const std::string &filename, const std::string &contents);
  ~TransientFile();

protected:
  std::string filename_;
};

// RAII class for a temporary file with the given contents.
class TempFile : public TransientFile {
public:
  TempFile(const std::string &contents);

  const char *filename() const
  {
    return filename_.c_str();
  }
};

// RAII class for a temporary environment variable value.
class EnvValue {
public:
  EnvValue(const char *name, const char *value) : name_(name), restore_(false)
  {
    char *original = getenv(name);
    if (original) {
      restore_  = true;
      original_ = original;
    }
    setenv(name_.c_str(), value, 1);
  }

  ~EnvValue()
  {
    if (restore_) {
      setenv(name_.c_str(), original_.c_str(), 1);
    } else {
      unsetenv(name_.c_str());
    }
  }

private:
  std::string name_;
  bool        restore_;
  std::string original_;
};

/* Assigns virtual IO functions to a channel */
class VirtualizeIO {
public:
  VirtualizeIO(ares_channel);
  ~VirtualizeIO();

  static const ares_socket_functions default_functions;

private:
  ares_channel_t *channel_;
};

#define VCLASS_NAME(casename, testname) Virt##casename##_##testname
#define VIRT_NONVIRT_TEST_F(casename, testname)                    \
  class VCLASS_NAME(casename, testname) : public casename {        \
  public:                                                          \
    VCLASS_NAME(casename, testname)()                              \
    {                                                              \
    }                                                              \
    void InnerTestBody();                                          \
  };                                                               \
  GTEST_TEST_(casename, testname, VCLASS_NAME(casename, testname), \
              ::testing::internal::GetTypeId<casename>())          \
  {                                                                \
    InnerTestBody();                                               \
  }                                                                \
  GTEST_TEST_(casename, testname##_virtualized,                    \
              VCLASS_NAME(casename, testname),                     \
              ::testing::internal::GetTypeId<casename>())          \
  {                                                                \
    VirtualizeIO vio(channel_);                                    \
    InnerTestBody();                                               \
  }                                                                \
  void VCLASS_NAME(casename, testname)::InnerTestBody()

// Event thread test fixtures
class MockEventThreadOptsTest : public MockChannelOptsTest {
public:
  MockEventThreadOptsTest(int count, ares_evsys_t evsys, int family,
                          bool force_tcp, struct ares_options *givenopts,
                          int optmask)
    : MockChannelOptsTest(count, family, force_tcp, false,
                          FillOptionsET(&evopts_, givenopts, evsys),
                          optmask | ARES_OPT_EVENT_THREAD)
  {
  }

  ~MockEventThreadOptsTest()
  {
  }

  static struct ares_options *FillOptionsET(struct ares_options *opts,
                                            struct ares_options *givenopts,
                                            ares_evsys_t         evsys)
  {
    if (givenopts) {
      memcpy(opts, givenopts, sizeof(*opts));
    } else {
      memset(opts, 0, sizeof(*opts));
    }
    opts->evsys = evsys;
    return opts;
  }

  void Process(unsigned int cancel_ms = 0);

private:
  struct ares_options evopts_;
};

class MockEventThreadTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int, bool>> {
public:
  MockEventThreadTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), std::get<2>(GetParam()),
                              nullptr, 0)
  {
  }
};

class MockUDPEventThreadTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int>> {
public:
  MockUDPEventThreadTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), false, nullptr, 0)
  {
  }
};

class MockTCPEventThreadTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int>> {
public:
  MockTCPEventThreadTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), true, nullptr, 0)
  {
  }
};

// Parameter sets for event thread tests
extern std::vector<std::tuple<ares_evsys_t, int, bool>> evsys_families_modes;
extern std::vector<std::tuple<ares_evsys_t, int>> evsys_families;

}  // namespace test
}  // namespace ares

#endif
