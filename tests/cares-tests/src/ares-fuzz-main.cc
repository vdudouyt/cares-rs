/*
 * Driver for fuzz corpus tests using the dlsym-based loader.
 * Takes library path as argv[1], remaining args are corpus files.
 *
 * Usage: ./aresfuzz path/to/libcares_rs.so fuzzinput/*
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "loader.h"

#define kMaxInputSize (1 << 20)
static unsigned char input_buffer[kMaxInputSize];

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data,
                                       unsigned long size);

static void ProcessFile(const char *filename)
{
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Failed to open '%s'\n", filename);
    return;
  }
  ssize_t count = read(fd, input_buffer, kMaxInputSize);
  close(fd);

  if (count > 0) {
    unsigned char *copied = (unsigned char *)malloc((size_t)count);
    memcpy(copied, input_buffer, (size_t)count);
    LLVMFuzzerTestOneInput(copied, (size_t)count);
    free(copied);
  }
}

int main(int argc, char *argv[])
{
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <library.so> <corpus_file> [...]\n", argv[0]);
    return 1;
  }

  load_cares_impl(argv[1]);

  for (int i = 2; i < argc; i++) {
    ProcessFile(argv[i]);
  }

  unload_cares_impl();
  return 0;
}
