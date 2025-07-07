#ifndef _TF_TAINT_H
#define _TF_TAINT_H

#include "libdft_api.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Enumerates the possible sources of taint.
 */
typedef enum {
  TS_NONE = 0,        //< no taint.
  TS_NETWORK = 1,     //< data from network.
  TS_FILE = 2,        //< data from file.
  TS_USER_INPUT = 3,  //< data from user input.
  TS_ENVIRONMENT = 4, //< data from environment variables.
  TS_STACK = 5,       //< data from stack reserved returns.
  TS_HEAP = 6,        //< data from heap allocations.
  TS_ARGUMENT = 7,    //< data from function arguments.
  TS_FREED = 8,       //< data from function returns.
  TS_CUSTOM1 = 9,     //< custom source type 1.
  TS_CUSTOM2 = 10,    //< custom source type 2.
  TS_CUSTOM3 = 11,    //< custom source type 3.
  TS_CUSTOM4 = 12,    //< custom source type 4.
  TS_PROPAGATED = 15  //< tag used for propagated taint from mixed sources.
} taint_source_t;

/**
 * @brief (API) Applies a custom taint tag to a specified memory region using libdft.
 * @param addr Start address of the memory region.
 * @param size Size of the memory region in bytes.
 * @param source_type The source of the taint (e.g., network, file).
 * @param level The confidence level of the taint (0-15).
 */
void
tf_region_taint(void *addr, size_t size, taint_source_t source_type, uint8_t level);

/**
 * @brief (API) Clears taint from a specified memory region in libdft.
 * @param addr Start address of the memory region to clear.
 * @param size Size of the memory region in bytes.
 */
void
tf_region_clear(void *addr, size_t size);

/**
 * @brief (API) Checks if any byte in a specified memory region is tainted according to libdft.
 * @param addr Start address of the memory region.
 * @param size Size of the memory region in bytes.
 * @return True if any byte in the region has a non-zero taint tag in libdft, false otherwise.
 */
bool
tf_region_check(void *addr, size_t size);

/**
 * @brief (API) Retrieves and decodes the libdft taint tag for a single memory address.
 * @param addr The memory address to query.
 * @param[out] source_type Pointer to store the extracted taint source type (can be NULL).
 * @param[out] level Pointer to store the extracted taint level (can be NULL).
 * @return The raw taint tag from libdft associated with the address.
 */
tag_t
tf_region_info(void *addr, taint_source_t *source_type, uint8_t *level);

////////////////////////
/* END OF HEADER FILE */
////////////////////////

//////////////////////////////////
/* vvv TAINT_IMPLEMENTATION vvv */
//////////////////////////////////

/**
 * Function definitions for the TaintFuzz Taint API
 * Note: if you want to use the definitions:
 * ```c
 * #define TAINT_IMPLEMENTATION
 * #include "taint.h"
 * ```
 */
#ifdef TAINT_IMPLEMENTATION

#define TAINT_MAX_SOURCE_TYPES 16   // 4 bits for source type
#define TAINT_SOURCE_TYPE_MASK 0x0F // Mask to extract source type
#define TAINT_LEVEL_SHIFT 4         // Bit shift for taint level
#define TAINT_LEVEL_MASK 0xF0       // Mask to extract taint level

#ifdef DEBUG_TAINT
#define TAINT_DEBUG(fmt, ...)                                                                      \
  printf("[TAINT] %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define TAINT_DEBUG(fmt, ...)                                                                      \
  do {                                                                                             \
  } while (0)
#endif

#define likely(x) __builtin_expect(!!(x), true)
#define unlikely(x) __builtin_expect(!!(x), false)

/**
 * @brief (Internal Utility) Returns a string representation of a taint source type.
 * @param source_type The taint source type.
 * @return String representation of the source type.
 */
static inline const char *
_tf_util_source_to_string(taint_source_t source_type) {
  switch (source_type) {
    case TS_NONE: return "NONE";
    case TS_NETWORK: return "NETWORK";
    case TS_FILE: return "FILE";
    case TS_USER_INPUT: return "USER_INPUT";
    case TS_ENVIRONMENT: return "ENVIRONMENT";
    case TS_STACK: return "STACK";
    case TS_HEAP: return "HEAP";
    case TS_ARGUMENT: return "ARGUMENT";
    case TS_FREED: return "FREED";
    case TS_CUSTOM1: return "CUSTOM1";
    case TS_CUSTOM2: return "CUSTOM2";
    case TS_CUSTOM3: return "CUSTOM3";
    case TS_CUSTOM4: return "CUSTOM4";
    case TS_PROPAGATED: return "PROPAGATED";
    default: return "UNKNOWN";
  }
}

/**
 * @brief (Internal Utility) Creates a taint tag from a source type and level.
 * @param source_type The type of taint source.
 * @param level The confidence level of the taint (0-15).
 * @return The combined taint tag.
 */
static inline tag_t
_tf_util_tag_create(taint_source_t source_type, uint8_t level) {
  assert(level <= 0x0F); // level must fit in 4 bits
  tag_t result = ((level << TAINT_LEVEL_SHIFT) | (source_type & TAINT_SOURCE_TYPE_MASK));
  TAINT_DEBUG("Creating tag: source=%s(%d), level=%u, tag=0x%lx", 
              _tf_util_source_to_string(source_type), (int)source_type, level,
              (unsigned long)result);
  return result;
}

/**
 * @brief (Internal Utility) Extracts the taint source type from a tag.
 * @param tag The taint tag.
 * @return The taint source type.
 */
static inline taint_source_t
_tf_util_tag_get_source(tag_t tag) {
  taint_source_t result = (taint_source_t)(tag & TAINT_SOURCE_TYPE_MASK);
  TAINT_DEBUG("Extracting source from tag: tag=0x%lx, source=%s(%d)", 
              (unsigned long)tag, _tf_util_source_to_string(result), (int)result);
  return result;
}

/**
 * @brief (Internal Utility) Extracts the taint level from a tag.
 * @param tag The taint tag.
 * @return The taint level (0-15).
 */
static inline uint8_t
_tf_util_tag_get_level(tag_t tag) {
  uint8_t result = (tag & TAINT_LEVEL_MASK) >> TAINT_LEVEL_SHIFT;
  TAINT_DEBUG("Extracting level from tag: tag=0x%lx, level=%u", (unsigned long)tag, result);
  return result;
}

/**
 * @brief (Internal Utility) Returns the minimum of two uint8_t values.
 * @param a First value.
 * @param b Second value.
 * @return The smaller of a and b.
 */
static inline uint8_t
_tf_util_min_u8(uint8_t a, uint8_t b) {
  return (a < b) ? a : b;
}

/**
 * @brief (Internal Utility) Returns the maximum of two uint8_t values.
 * @param a First value.
 * @param b Second value.
 * @return The larger of a and b.
 */
static inline uint8_t
_tf_util_max_u8(uint8_t a, uint8_t b) {
  return (a > b) ? a : b;
}

/**
 * @brief (Internal Utility) Combines two taint tags.
 * The resulting tag takes the highest confidence level. If source types differ,
 * the result is marked as TS_PROPAGATED.
 * @param t1 First taint tag.
 * @param t2 Second taint tag.
 * @return The combined taint tag.
 */
static inline tag_t
_tf_util_combine_tag(tag_t t1, tag_t t2) {
  if (t1 == 0)
    return t2;
  if (t2 == 0)
    return t1;

  taint_source_t src1 = _tf_util_tag_get_source(t1);
  taint_source_t src2 = _tf_util_tag_get_source(t2);
  uint8_t lvl1 = _tf_util_tag_get_level(t1);
  uint8_t lvl2 = _tf_util_tag_get_level(t2);

  taint_source_t result_src = (src1 == src2) ? src1 : TS_PROPAGATED;
  uint8_t result_lvl = _tf_util_max_u8(lvl1, lvl2);

  tag_t result = _tf_util_tag_create(result_src, result_lvl);
  TAINT_DEBUG("Combining tags: t1=0x%lx(%s,%u), t2=0x%lx(%s,%u) => result=0x%lx(%s,%u)",
              (unsigned long)t1, _tf_util_source_to_string(src1), lvl1, 
              (unsigned long)t2, _tf_util_source_to_string(src2), lvl2, 
              (unsigned long)result, _tf_util_source_to_string(result_src), result_lvl);
  return result;
}

/**
 * @brief (API) Applies a custom taint tag to a specified memory region using libdft.
 */
void
tf_region_taint(void *addr, size_t size, taint_source_t source_type, uint8_t level) {
  if (unlikely(!addr || size == 0)) {
    TAINT_DEBUG("Operation failed: invalid parameters (addr=%p, size=%zu)", addr, size);
    return;
  }

  uintptr_t low_addr = (uintptr_t)addr;
  uintptr_t high_addr = low_addr + size - 1;

  if (high_addr < low_addr) {
    TAINT_DEBUG("Operation failed: address overflow (start=0x%lx, size=%zu)", low_addr, size);
    return;
  }

  TAINT_DEBUG("Applying taint: region=0x%lx-0x%lx (size=%zu), source=%s(%d), level=%u", 
              low_addr, high_addr, size, _tf_util_source_to_string(source_type), 
              (int)source_type, level);

  tag_t tag_to_apply = _tf_util_tag_create(source_type, level);

  // apply taint tags to memory via libdft
  for (uintptr_t curr_addr = low_addr; curr_addr <= high_addr; curr_addr++) {
    tagmap_setb(curr_addr, tag_to_apply);
    if (curr_addr == high_addr) {
      break; // avoid overflow if high_addr is UINTPTR_MAX
    }
  }
  TAINT_DEBUG("Taint application completed: region=0x%lx-0x%lx", low_addr, high_addr);
}

/**
 * @brief (API) Clears taint from a specified memory region in libdft.
 */
void
tf_region_clear(void *addr, size_t size) {
  if (unlikely(!addr || size == 0)) {
    TAINT_DEBUG("Operation failed: invalid parameters (addr=%p, size=%zu)", addr, size);
    return;
  }

  uintptr_t clear_low_addr = (uintptr_t)addr;
  uintptr_t clear_high_addr = clear_low_addr + size - 1;

  if (clear_high_addr < clear_low_addr) { // overflow check
    TAINT_DEBUG("Operation failed: address overflow (start=0x%lx, size=%zu)", clear_low_addr, size);
    return;
  }

  TAINT_DEBUG("Clearing taint: region=0x%lx-0x%lx (size=%zu)", clear_low_addr, clear_high_addr, size);

  // clear actual byte tags using libdft for the specified range
  for (uintptr_t curr_addr = clear_low_addr; curr_addr <= clear_high_addr; curr_addr++) {
    tagmap_clrb(curr_addr);
    if (curr_addr == clear_high_addr) {
      break; // avoid overflow
    }
  }
  TAINT_DEBUG("Taint clearing completed: region=0x%lx-0x%lx", clear_low_addr, clear_high_addr);
}

/**
 * @brief (API) Checks if any byte in a specified memory region is tainted according to libdft.
 */
bool
tf_region_check(void *addr, size_t size) {
  if (unlikely(!addr || size == 0)) {
    TAINT_DEBUG("Operation failed: invalid parameters (addr=%p, size=%zu)", addr, size);
    return false;
  }

  uintptr_t low_addr = (uintptr_t)addr;
  uintptr_t high_addr = low_addr + size - 1;

  if (high_addr < low_addr) { // overflow
    TAINT_DEBUG("Operation failed: address overflow (start=0x%lx, size=%zu)", low_addr, size);
    return false;
  }

  TAINT_DEBUG("Checking taint: region=0x%lx-0x%lx (size=%zu)", low_addr, high_addr, size);

  for (uintptr_t curr_addr = low_addr; curr_addr <= high_addr; curr_addr++) {
    tag_t tag = tagmap_getb(curr_addr); // query libdft
    if (tag != 0) {
      taint_source_t source = _tf_util_tag_get_source(tag);
      uint8_t level = _tf_util_tag_get_level(tag);
      TAINT_DEBUG("Taint found: addr=0x%lx, tag=0x%lx, source=%s(%d), level=%u", 
                  curr_addr, (unsigned long)tag, _tf_util_source_to_string(source), 
                  (int)source, level);
      return true;
    }
    if (curr_addr == high_addr) {
      break; // avoid overflow
    }
  }

  TAINT_DEBUG("Taint check completed: no taint found in region=0x%lx-0x%lx", low_addr, high_addr);
  return false;
}

/**
 * @brief (API) Retrieves and decodes the libdft taint tag for a single memory address.
 */
tag_t
tf_region_info(void *addr, taint_source_t *source_type, uint8_t *level) {
  if (unlikely(!addr)) {
    TAINT_DEBUG("Operation failed: invalid address (null)");
    if (source_type) {
      *source_type = TS_NONE;
    }
    if (level) {
      *level = 0;
    }
    return 0;
  }

  uintptr_t address = (uintptr_t)addr;
  tag_t tag = tagmap_getb(address); // query libdft

  taint_source_t src = _tf_util_tag_get_source(tag);
  uint8_t lvl = _tf_util_tag_get_level(tag);

  TAINT_DEBUG("Taint info retrieved: addr=0x%lx, tag=0x%lx, source=%s(%d), level=%u", 
              address, (unsigned long)tag, _tf_util_source_to_string(src), (int)src, lvl);

  if (source_type != NULL) {
    *source_type = src;
  }
  if (level != NULL) {
    *level = lvl;
  }
  return tag;
}

#endif // TAINT_IMPLEMENTATION
#endif // _TF_TAINT_H
