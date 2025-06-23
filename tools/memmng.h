#ifndef _TF_MEMMNG_H
#define _TF_MEMMNG_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void
tf_mem_init(void);
void
tf_mem_die(void);
void
tf_mem_register(void *address, size_t size);
void
tf_mem_unregister(void *address);

typedef struct {
  uintptr_t low;
  size_t offset;
} mem_segment_t;

typedef struct {
  mem_segment_t *segments;
  size_t size;
  size_t next;
} memory_manager_t;

static memory_manager_t memory_manager;

#define MEMMNG_CHUNK 32
void
tf_mem_init(void) {
  memory_manager.next = 0;
  memory_manager.size = MEMMNG_CHUNK;
  memory_manager.segments = (mem_segment_t *)malloc(memory_manager.size * sizeof(mem_segment_t));
  if (memory_manager.segments == NULL) {
    fprintf(stdout, "memmng init fail\n");
    return;
  }
}

void
tf_mem_die(void) {
  free(memory_manager.segments);
  memory_manager.segments = NULL;
  memory_manager.size = 0;
  memory_manager.next = 0;
  return;
}

void
tf_mem_register(void *address, size_t size) {
  if (memory_manager.next == memory_manager.size - 1) {
    memory_manager.size *= 2;
    memory_manager.segments = (mem_segment_t *)realloc(memory_manager.segments,
                                                       memory_manager.size * sizeof(mem_segment_t));
    if (memory_manager.segments == NULL) {
      fprintf(stdout, "memmng realloc fail\n");
      return;
    }
  }

  // add new segment
  memory_manager.segments[memory_manager.next].low = (uintptr_t)address;
  memory_manager.segments[memory_manager.next].offset = size;
  memory_manager.next += 1;
}

void
tf_mem_unregister(void *address) {
  for (size_t i = 0; i < memory_manager.next; ++i) {
    if (memory_manager.segments[i].low == (uintptr_t)address) {
      memory_manager.segments[i].low = (uintptr_t)NULL;
      memory_manager.segments[i].offset = 0;
    }
  }
  // TODO: actually manage the list
}

size_t
tf_mem_get_size(void *address) {
  for (size_t i = 0; i < memory_manager.next; ++i) {
    if (memory_manager.segments[i].low == (uintptr_t)address) {
      return memory_manager.segments[i].offset;
    }
  }
  return 0;
}

#endif // _TF_MEMMNG_H
