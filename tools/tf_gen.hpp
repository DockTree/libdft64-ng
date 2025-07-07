#ifndef TF_GEN_H
#define TF_GEN_H

// signature description file
#include <stdint.h>
#define GENERATED_SIGS "tf_std_sig.inc"

#define FUNCTION_ARG_LIMIT 6
enum io_flag_t { IO_SRC = 1 << 0, IO_SINK = 1 << 1, NO_IO = 1 << 2 };
typedef struct {
  std::string name;
  uint32_t flags;
  uint32_t nargs;
  int8_t len_map[FUNCTION_ARG_LIMIT]; // -1 = ignore, otherwise argidx
} sig_entry_t;

// generated headers
#define TF_SIG_ENTRY(name, flags, argc, ...) {name, flags, argc, {__VA_ARGS__}},
sig_entry_t tf_sig_table[] = {
#include GENERATED_SIGS
};
#undef TF_SIG_ENTRY

#endif // !TF_GEN_H
