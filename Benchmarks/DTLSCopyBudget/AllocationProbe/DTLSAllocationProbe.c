#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct allocation_probe_counters {
  _Atomic uint64_t malloc_calls;
  _Atomic uint64_t malloc_bytes;
  _Atomic uint64_t calloc_calls;
  _Atomic uint64_t calloc_bytes;
  _Atomic uint64_t realloc_calls;
  _Atomic uint64_t realloc_bytes;
  _Atomic uint64_t aligned_calls;
  _Atomic uint64_t aligned_bytes;
  _Atomic uint64_t free_calls;
  _Atomic uint64_t memcpy_calls;
  _Atomic uint64_t memcpy_bytes;
  _Atomic uint64_t memmove_calls;
  _Atomic uint64_t memmove_bytes;
};

static _Atomic bool probe_enabled = false;
static struct allocation_probe_counters counters;

// The process owns this interposed image until exit. The probe stores no caller
// pointers, never dereferences caller memory, and uses relaxed atomic counters
// behind an acquire/release measurement toggle. dyld routes calls from other
// images here while this image's own libc calls continue to libSystem.

static uint64_t requested_product(size_t count, size_t size) {
  if (size != 0 && count > UINT64_MAX / size) {
    return UINT64_MAX;
  }
  return (uint64_t)count * (uint64_t)size;
}

static void reset_counter(_Atomic uint64_t *counter) {
  atomic_store_explicit(counter, 0, memory_order_relaxed);
}

static void add_counter(_Atomic uint64_t *counter, uint64_t value) {
  uint64_t current = atomic_load_explicit(counter, memory_order_relaxed);
  while (true) {
    uint64_t next = value > UINT64_MAX - current ? UINT64_MAX : current + value;
    if (atomic_compare_exchange_weak_explicit(
            counter,
            &current,
            next,
            memory_order_relaxed,
            memory_order_relaxed)) {
      return;
    }
  }
}

static uint64_t load_counter(_Atomic uint64_t *counter) {
  return atomic_load_explicit(counter, memory_order_relaxed);
}

void swift_tls_allocation_probe_start(void) {
  reset_counter(&counters.malloc_calls);
  reset_counter(&counters.malloc_bytes);
  reset_counter(&counters.calloc_calls);
  reset_counter(&counters.calloc_bytes);
  reset_counter(&counters.realloc_calls);
  reset_counter(&counters.realloc_bytes);
  reset_counter(&counters.aligned_calls);
  reset_counter(&counters.aligned_bytes);
  reset_counter(&counters.free_calls);
  reset_counter(&counters.memcpy_calls);
  reset_counter(&counters.memcpy_bytes);
  reset_counter(&counters.memmove_calls);
  reset_counter(&counters.memmove_bytes);
  atomic_store_explicit(&probe_enabled, true, memory_order_release);
}

void swift_tls_allocation_probe_stop_and_print(void) {
  atomic_store_explicit(&probe_enabled, false, memory_order_release);
  printf(
      "ALLOCATION_RESULT,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
      "%llu,%llu,%llu,%llu\n",
      load_counter(&counters.malloc_calls),
      load_counter(&counters.malloc_bytes),
      load_counter(&counters.calloc_calls),
      load_counter(&counters.calloc_bytes),
      load_counter(&counters.realloc_calls),
      load_counter(&counters.realloc_bytes),
      load_counter(&counters.aligned_calls),
      load_counter(&counters.aligned_bytes),
      load_counter(&counters.free_calls),
      load_counter(&counters.memcpy_calls),
      load_counter(&counters.memcpy_bytes),
      load_counter(&counters.memmove_calls),
      load_counter(&counters.memmove_bytes));
}

static bool is_enabled(void) {
  return atomic_load_explicit(&probe_enabled, memory_order_acquire);
}

static void *probe_malloc(size_t size) {
  void *result = malloc(size);
  if (is_enabled()) {
    add_counter(&counters.malloc_calls, 1);
    add_counter(&counters.malloc_bytes, size);
  }
  return result;
}

static void *probe_calloc(size_t count, size_t size) {
  void *result = calloc(count, size);
  if (is_enabled()) {
    add_counter(&counters.calloc_calls, 1);
    add_counter(&counters.calloc_bytes, requested_product(count, size));
  }
  return result;
}

static void *probe_realloc(void *pointer, size_t size) {
  void *result = realloc(pointer, size);
  if (is_enabled()) {
    add_counter(&counters.realloc_calls, 1);
    add_counter(&counters.realloc_bytes, size);
  }
  return result;
}

static int probe_posix_memalign(void **pointer, size_t alignment, size_t size) {
  int result = posix_memalign(pointer, alignment, size);
  if (result == 0 && is_enabled()) {
    add_counter(&counters.aligned_calls, 1);
    add_counter(&counters.aligned_bytes, size);
  }
  return result;
}

static void *probe_aligned_alloc(size_t alignment, size_t size) {
  void *result = aligned_alloc(alignment, size);
  if (result != NULL && is_enabled()) {
    add_counter(&counters.aligned_calls, 1);
    add_counter(&counters.aligned_bytes, size);
  }
  return result;
}

static void probe_free(void *pointer) {
  bool counted = pointer != NULL && is_enabled();
  free(pointer);
  if (counted) {
    add_counter(&counters.free_calls, 1);
  }
}

static void *probe_memcpy(void *destination, const void *source, size_t size) {
  void *result = memcpy(destination, source, size);
  if (is_enabled()) {
    add_counter(&counters.memcpy_calls, 1);
    add_counter(&counters.memcpy_bytes, size);
  }
  return result;
}

static void *probe_memmove(void *destination, const void *source, size_t size) {
  void *result = memmove(destination, source, size);
  if (is_enabled()) {
    add_counter(&counters.memmove_calls, 1);
    add_counter(&counters.memmove_bytes, size);
  }
  return result;
}

#define DYLD_INTERPOSE(replacement, replacee)                                \
  __attribute__((used)) static struct {                                      \
    const void *replacement;                                                 \
    const void *replacee;                                                    \
  } _interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
      (const void *)(uintptr_t)&replacement,                                 \
      (const void *)(uintptr_t)&replacee,                                    \
  }

DYLD_INTERPOSE(probe_malloc, malloc);
DYLD_INTERPOSE(probe_calloc, calloc);
DYLD_INTERPOSE(probe_realloc, realloc);
DYLD_INTERPOSE(probe_posix_memalign, posix_memalign);
DYLD_INTERPOSE(probe_aligned_alloc, aligned_alloc);
DYLD_INTERPOSE(probe_free, free);
DYLD_INTERPOSE(probe_memcpy, memcpy);
DYLD_INTERPOSE(probe_memmove, memmove);
