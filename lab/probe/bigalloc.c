/* bigalloc.c — LD_PRELOAD logger for regex2shell stage-3 layout work.
 *
 * Logs every malloc/free >= BIG_MIN bytes to stderr as:
 *   A sz=<n> ptr=0x.. caller=0x..   (malloc)
 *   F ptr=0x.. sz=<n>               (free)
 * so the engine's compile-time and match-time allocations (program,
 * repeat_range, repeat_stk) can be mapped onto /proc/self/maps and owned
 * to a VMA region. Sizes are tracked in a side table keyed by ptr.
 * Ruby heap pages (64 KiB) are included by BIG_MIN=60000.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

#define BIG_MIN 4000UL

static void *(*real_malloc)(size_t);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);
static int (*real_pmemalign)(void **, size_t, size_t);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct rec { void *p; size_t sz; struct rec *next; };
static struct rec *recs;

static void log_a(void *p, size_t sz, void *caller) {
  if (sz >= BIG_MIN)
    fprintf(stderr, "A sz=%zu ptr=%p caller=%p\n", sz, p, caller);
}

static void remember(void *p, size_t sz) {
  struct rec *r = real_malloc(sizeof(*r));
  if (!r) return;
  r->p = p; r->sz = sz; r->next = recs; recs = r;
}

static size_t forget(void *p) {
  for (struct rec **pp = &recs; *pp; pp = &(*pp)->next) {
    if ((*pp)->p == p) {
      size_t sz = (*pp)->sz;
      struct rec *dead = *pp;
      *pp = dead->next;
      real_free(dead);
      return sz;
    }
  }
  return 0;
}

static void init(void) {
  if (!real_malloc) {
    real_malloc    = dlsym(RTLD_NEXT, "malloc");
    real_realloc   = dlsym(RTLD_NEXT, "realloc");
    real_free      = dlsym(RTLD_NEXT, "free");
    real_pmemalign = dlsym(RTLD_NEXT, "posix_memalign");
  }
}

void *malloc(size_t sz) {
  init();
  void *p = real_malloc(sz);
  if (sz >= BIG_MIN) {
    pthread_mutex_lock(&lock);
    remember(p, sz);
    log_a(p, sz, __builtin_return_address(0));
    pthread_mutex_unlock(&lock);
  }
  return p;
}

void *realloc(void *old, size_t sz) {
  init();
  void *p = real_realloc(old, sz);
  if (sz >= BIG_MIN) {
    pthread_mutex_lock(&lock);
    if (old) forget(old);
    remember(p, sz);
    log_a(p, sz, __builtin_return_address(0));
    pthread_mutex_unlock(&lock);
  }
  return p;
}

int posix_memalign(void **out, size_t align, size_t sz) {
  init();
  int rc = real_pmemalign(out, align, sz);
  if (rc == 0 && sz >= BIG_MIN) {
    pthread_mutex_lock(&lock);
    remember(*out, sz);
    fprintf(stderr, "P sz=%zu align=%zu ptr=%p caller=%p\n", sz, align, *out,
            __builtin_return_address(0));
    pthread_mutex_unlock(&lock);
  }
  return rc;
}

void free(void *p) {
  init();
  if (p) {
    pthread_mutex_lock(&lock);
    size_t sz = forget(p);
    if (sz) fprintf(stderr, "F ptr=%p sz=%zu\n", p, sz);
    pthread_mutex_unlock(&lock);
  }
  real_free(p);
}
