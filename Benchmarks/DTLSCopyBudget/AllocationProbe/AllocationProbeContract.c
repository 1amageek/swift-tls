#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*probe_control)(void);

static volatile size_t memcpy_size = 13;
static volatile size_t memmove_size = 7;

__attribute__((noinline, optnone)) static void call_memcpy(
    void *destination,
    const void *source) {
  memcpy(destination, source, memcpy_size);
}

__attribute__((noinline, optnone)) static void call_memmove(
    void *destination,
    const void *source) {
  memmove(destination, source, memmove_size);
}

int main(void) {
  probe_control start = (probe_control)dlsym(
      RTLD_DEFAULT,
      "swift_tls_allocation_probe_start");
  probe_control stop_and_print = (probe_control)dlsym(
      RTLD_DEFAULT,
      "swift_tls_allocation_probe_stop_and_print");
  if (start == NULL || stop_and_print == NULL) {
    return 2;
  }

  unsigned char source[32];
  unsigned char destination[32];
  for (size_t index = 0; index < sizeof(source); index += 1) {
    source[index] = (unsigned char)(index * 7U);
    destination[index] = 0;
  }

  start();
  void *first = malloc(17);
  void *second = calloc(2, 19);
  void *third = realloc(NULL, 41);
  void *aligned = NULL;
  int alignment_result = posix_memalign(&aligned, 64, 128);
  call_memcpy(destination, source);
  call_memmove(destination + 5, destination);
  bool allocations_succeeded =
      first != NULL && second != NULL && third != NULL && alignment_result == 0
      && aligned != NULL;
  free(first);
  free(second);
  free(third);
  free(aligned);
  stop_and_print();

  if (!allocations_succeeded) {
    return 3;
  }

  uint64_t checksum = 0;
  for (size_t index = 0; index < sizeof(destination); index += 1) {
    checksum += destination[index];
  }
  printf("PROBE_CHECKSUM,%llu\n", (unsigned long long)checksum);
  return 0;
}
