#ifndef TF_TYPE_HPP
#define TF_TYPE_HPP

#include <cstdint>
#include <vector>

typedef enum {
  UNKNOWN = 0,
  MAPPED_PTR,
  HEAP_PTR,
  STACK_PTR,
  LIB_PTR,
  SIZE_ARG,   // likely a size argument
  FD_ARG,     // likely a file descriptor
  FLAGS_ARG,  // likely flags/options
  SMALL_INT,  // small integer value
  NULL_PTR,   // NULL pointer
  INVALID_PTR // invalid pointer value
} tf_type_t;

const char *
type_to_string(tf_type_t type) {
  switch (type) {
  case UNKNOWN:
    return "UNKNOWN";
  case MAPPED_PTR:
    return "ANON";
  case HEAP_PTR:
    return "HEAP";
  case STACK_PTR:
    return "STACK";
  case LIB_PTR:
    return "LIB";
  case SIZE_ARG:
    return "SIZE_ARG";
  case FD_ARG:
    return "FD_ARG";
  case FLAGS_ARG:
    return "FLAGS_ARG";
  case SMALL_INT:
    return "SMALL_INT";
  case NULL_PTR:
    return "NULL_PTR";
  case INVALID_PTR:
    return "INVALID_PTR";
  default:
    return "INVALID";
  }
}

struct memory_region_t {
  uintptr_t start;
  uintptr_t end;
  tf_type_t type;
  std::string path;
};

// singleton global vector :)
static std::vector<memory_region_t> g_memory_map;

void
refresh_memory_map() {
  g_memory_map.clear();

  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp)
    return;

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    uintptr_t start, end;
    char perms[5];
    char path[256] = "";

    int matched = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path);
    if (matched >= 3 && perms[0] == 'r') {
      tf_type_t type = UNKNOWN;
      if (strcmp(path, "[heap]") == 0)
        type = HEAP_PTR;
      else if (strcmp(path, "[stack]") == 0 || strstr(path, "[stack:"))
        type = STACK_PTR;
      else if (strstr(path, ".so") || strstr(path, "/lib"))
        type = LIB_PTR;
      else if (strlen(path) == 0)
        type = MAPPED_PTR;

      memory_region_t region = {start, end, type, path};
      g_memory_map.push_back(region);

      /*fprintf(stdout, "[MAP] %lx-%lx perms: %s type: %d path: %s\n",*/
      /*        start, end, perms, type, strlen(path) ? path : "[anonymous]");*/
    }
  }

  fclose(fp);
}

tf_type_t
guess_argument_type(ADDRINT value) {
  if (value == 0) {
    return NULL_PTR;
  }

  // check for small integers
  if (value <= 0xFFFF) { // 16-bit range
    if (value <= 10) {
      // very small values are often file descriptors
      return FD_ARG;
    } else if (value <= 65536) {
      // medium small values often sizes or counts
      return SIZE_ARG;
    }
    return SMALL_INT;
  }

  // check for common flag patterns
  if (value != 0 && (value & (value - 1)) == 0) {
    // power of 2, likely a flag
    return FLAGS_ARG;
  }

  // check for typical size ranges
  if (value >= 256 && value <= 0x40000000) { // .2KB to 1GB
    // could be a size argument
    return SIZE_ARG;
  }

// check if it looks like a valid pointer range but unmapped
#ifdef __x86_64__
  if (value >= 0x400000 && value < 0x800000000000ULL) {
    // typical x86_64 user space range but not mapped
    return INVALID_PTR;
  }
#else
  if (value >= 0x8000 && value < 0xC0000000) {
    // typical 32-bit user space range but not mapped
    return INVALID_PTR;
  }
#endif

  return UNKNOWN;
}

void
print_typed_value(ADDRINT ptr, tf_type_t type) {
  switch (type) {
  case NULL_PTR:
    fprintf(stdout, "[CMR] check NULL for memory type: %s\n", type_to_string(type));
    break;
  case FD_ARG:
  case SMALL_INT:
  case SIZE_ARG:
    fprintf(stdout, "[CMR] check %lu (%lx) for memory type: %s\n", ptr, ptr, type_to_string(type));
    break;
  case FLAGS_ARG:
    fprintf(stdout, "[CMR] check 0x%lx (flags) for memory type: %s\n", ptr, type_to_string(type));
    break;
  case HEAP_PTR:
  case STACK_PTR:
  case LIB_PTR:
  case MAPPED_PTR:
  case INVALID_PTR:
  default:
    fprintf(stdout, "[CMR] check %lx for memory type: %s\n", ptr, type_to_string(type));
    break;
  }
}

tf_type_t
tf_check_type(ADDRINT value) {
  tf_type_t type = UNKNOWN;

  for (const auto &region : g_memory_map) {
    if (value >= region.start && value < region.end) {
      type = region.type;
      break;
    }
  }

  if (type == UNKNOWN) {
    type = guess_argument_type(value);
  }

  print_typed_value(value, type);

  return type;
}

#endif // !TF_TYPE_HPP
