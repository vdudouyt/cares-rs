/* Minimal ares_buf implementation for fuzz test support.
   The real ares_buf is internal to c-ares; this provides just
   the string-builder functions used by ares-test-fuzz.c. */
#ifndef ARES_BUF_H
#define ARES_BUF_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
  char  *data;
  size_t len;
  size_t cap;
} ares_buf_t;

static inline ares_buf_t *ares_buf_create(void) {
  ares_buf_t *buf = (ares_buf_t *)calloc(1, sizeof(ares_buf_t));
  if (buf) {
    buf->cap = 256;
    buf->data = (char *)malloc(buf->cap);
    if (buf->data) buf->data[0] = '\0';
  }
  return buf;
}

static inline void ares_buf_destroy(ares_buf_t *buf) {
  if (buf) { free(buf->data); free(buf); }
}

static inline void ares_buf_ensure(ares_buf_t *buf, size_t extra) {
  if (buf->len + extra + 1 > buf->cap) {
    size_t newcap = (buf->len + extra + 1) * 2;
    char *newdata = (char *)realloc(buf->data, newcap);
    if (newdata) { buf->data = newdata; buf->cap = newcap; }
  }
}

static inline ares_status_t ares_buf_append_str(ares_buf_t *buf, const char *str) {
  if (!buf || !str) return ARES_EBADQUERY;
  size_t slen = strlen(str);
  ares_buf_ensure(buf, slen);
  memcpy(buf->data + buf->len, str, slen);
  buf->len += slen;
  buf->data[buf->len] = '\0';
  return ARES_SUCCESS;
}

static inline ares_status_t ares_buf_append_byte(ares_buf_t *buf, unsigned char byte) {
  if (!buf) return ARES_EBADQUERY;
  ares_buf_ensure(buf, 1);
  buf->data[buf->len++] = (char)byte;
  buf->data[buf->len] = '\0';
  return ARES_SUCCESS;
}

static inline ares_status_t ares_buf_append_num_dec(ares_buf_t *buf, size_t num, size_t min_width) {
  if (!buf) return ARES_EBADQUERY;
  char tmp[32];
  (void)min_width;
  snprintf(tmp, sizeof(tmp), "%zu", num);
  return ares_buf_append_str(buf, tmp);
}

static inline ares_status_t ares_buf_append_num_hex(ares_buf_t *buf, size_t num, size_t min_width) {
  if (!buf) return ARES_EBADQUERY;
  char tmp[32];
  (void)min_width;
  snprintf(tmp, sizeof(tmp), "%zx", num);
  return ares_buf_append_str(buf, tmp);
}

static inline char *ares_buf_finish_str(ares_buf_t *buf, size_t *len) {
  if (!buf) return NULL;
  char *result = buf->data;
  if (len) *len = buf->len;
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
  free(buf);
  return result;
}

#endif /* ARES_BUF_H */
