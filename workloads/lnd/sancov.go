package lnd

/*
#cgo CFLAGS: -fPIC

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static uint8_t *__coverage_map = NULL;
static size_t __coverage_map_size = 0;
static int __coverage_initialized = 0;

// Track multiple counter regions (from different instrumented modules).
#define MAX_COUNTER_REGIONS 128

struct counter_region {
  uint8_t *start;
  uint8_t *end;
};

static struct counter_region __counter_regions[MAX_COUNTER_REGIONS];
static size_t __num_regions = 0;
static size_t __total_counters = 0;

static int __init_coverage_map(void) {
  if (__coverage_initialized) {
    return 1;
  }

  const char *shm_id_str = getenv("__AFL_SHM_ID");
  if (!shm_id_str) {
    printf("Warning: __AFL_SHM_ID not set, coverage tracking disabled\n");
    return 0;
  }
  const char *map_size_str = getenv("AFL_MAP_SIZE");
  if (!map_size_str) {
    printf("Warning: AFL_MAP_SIZE not set, coverage tracking disabled\n");
    return 0;
  }

  int shm_id = atoi(shm_id_str);
  if (shm_id < 0) {
    printf("Warning: Invalid __AFL_SHM_ID value: %s\n", shm_id_str);
    return 0;
  }

  __coverage_map = (uint8_t *)shmat(shm_id, NULL, 0);
  if (__coverage_map == (void *)-1) {
    printf("Warning: Failed to attach to shared memory segment %d\n", shm_id);
    __coverage_map = NULL;
    return 0;
  }

  __coverage_map_size = (size_t)atoi(map_size_str);

  printf("Coverage map initialized: %p (size: %zu)\n", __coverage_map,
         __coverage_map_size);
  __coverage_initialized = 1;
  return 1;
}

// Copy all counter regions to AFL shared memory.
void sancov_copy_coverage_to_shmem(void) {
  if (!__coverage_map || __num_regions == 0) {
    return;
  }

  size_t offset = 0;
  for (size_t i = 0; i < __num_regions && offset < __coverage_map_size; ++i) {
    size_t region_size = __counter_regions[i].end - __counter_regions[i].start;
    size_t copy_size = region_size;
    if (offset + copy_size > __coverage_map_size) {
      copy_size = __coverage_map_size - offset;
    }
    memcpy(__coverage_map + offset, __counter_regions[i].start, copy_size);
    offset += copy_size;
  }
}

void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end) {
  // PC table not used for AFL coverage.
}

// Called by Go's libfuzzer instrumentation to register coverage counters.
// May be called multiple times if multiple modules are instrumented.
void __sanitizer_cov_8bit_counters_init(char *start, char *end) {
  const char *dump_map_size_str = getenv("AFL_DUMP_MAP_SIZE");
  if (dump_map_size_str) {
    printf("%zu\n", (size_t)(end - start));
    exit(0);
  }

  __init_coverage_map();

  if (__num_regions >= MAX_COUNTER_REGIONS) {
    fprintf(stderr, "Error: Too many counter regions (max %d)\n",
            MAX_COUNTER_REGIONS);
    exit(1);
  }
  size_t region_size = end - start;
  __counter_regions[__num_regions].start = (uint8_t *)start;
  __counter_regions[__num_regions].end = (uint8_t *)end;
  ++__num_regions;
  __total_counters += region_size;

  if (__coverage_map) {
    printf("Registered counter region %zu: %zu counters\n", __num_regions,
           region_size);

    if (__total_counters > __coverage_map_size) {
      printf("Warning: Total counter size (%zu) exceeds map size (%zu)\n",
             __total_counters, __coverage_map_size);
    }
  }
}

// Empty stubs for comparison tracing hooks. Go's libfuzzer instrumentation
// emits calls to these, so we need to provide them to satisfy the linker.
// Marked weak so they can be overridden by real implementations if desired.
__attribute__((weak)) void __sanitizer_cov_trace_cmp1(uint8_t arg1,
                                                      uint8_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_cmp2(uint16_t arg1,
                                                      uint16_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_cmp4(uint32_t arg1,
                                                      uint32_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_cmp8(uint64_t arg1,
                                                      uint64_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp1(uint8_t arg1,
                                                            uint8_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp2(uint16_t arg1,
                                                            uint16_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp4(uint32_t arg1,
                                                            uint32_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp8(uint64_t arg1,
                                                            uint64_t arg2) {}

__attribute__((weak)) void __sanitizer_weak_hook_strcmp(const char *s1,
                                                        const char *s2) {}
*/
import "C"

import (
	"os"
	"strconv"
	"sync"
)

// This file provides coverage tracking for Go programs built with -d=libfuzzer.
// It integrates with AFL's shared memory coverage tracking.
//
// Coverage sync is triggered via pipe IPC:
// - Scenario requests a sync by writing a byte to the trigger fd
// - Coverage loop reads from the trigger fd, copies coverage, and writes to the
//   ack fd
// - Scenario reads from ack fd (synchronous handshake)

var coverageLoopOnce sync.Once

func init() {
	// Only start coverage loop if we're in fuzzing mode
	if os.Getenv("__AFL_SHM_ID") == "" {
		return
	}

	triggerFdStr := os.Getenv("COVERAGE_TRIGGER_FD")
	ackFdStr := os.Getenv("COVERAGE_ACK_FD")
	if triggerFdStr == "" || ackFdStr == "" {
		return
	}

	triggerFd, err := strconv.Atoi(triggerFdStr)
	if err != nil {
		return
	}
	ackFd, err := strconv.Atoi(ackFdStr)
	if err != nil {
		return
	}

	coverageLoopOnce.Do(func() {
		triggerFile := os.NewFile(uintptr(triggerFd), "coverage_trigger")
		ackFile := os.NewFile(uintptr(ackFd), "coverage_ack")

		go func() {
			defer triggerFile.Close()
			defer ackFile.Close()

			buf := make([]byte, 1)
			for {
				// Wait for request to copy coverage
				_, err := triggerFile.Read(buf)
				if err != nil {
					return // Pipe closed, exit loop
				}

				C.sancov_copy_coverage_to_shmem()

				// Signal that coverage has been copied
				ackFile.Write(buf)
			}
		}()
	})
}
