#ifndef TF_TOOLS_H
#define TF_TOOLS_H

#include <map>

#include "pin.H"

#include "tf_mem.hpp"

#define DEBUG_TAINT
#define TAINT_IMPLEMENTATION
#include "tf_taint.h"

#include "tf_gen.hpp"

#include "tf_type.hpp"

// Unified logging macros for consistency
#define LOG_INFO(fmt, ...) fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) fprintf(stdout, "[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define LOG_TAINT(fmt, ...) fprintf(stdout, "[TAINT] " fmt "\n", ##__VA_ARGS__)
#define LOG_ALERT(fmt, ...) fprintf(stdout, "[ALERT] " fmt "\n", ##__VA_ARGS__)

/*
 * Exposed context for pre-post HOOK communication
 */
struct tf_hook_ctx_t {
  THREADID tid;
  std::string name;
  ADDRINT func_addr;
  std::vector<ADDRINT *> arg_addr;
  std::vector<ADDRINT> arg_val;
  ADDRINT ret_val;
  uintptr_t etc;
};

// Global logger instance
#include "logger.h"

// --- Generic Hook Callbacks ---
static void
generic_pre(tf_hook_ctx_t *ctx) {
  if (!ctx) {
    LOG_ERROR("T%d: NULL context in generic_pre", PIN_ThreadId());
    return;
  }

  // fetch the memory mapping
  // from /proc/self/maps
  // TODO: find a balance, when to call
  // maybe monitor memory usage and only refresh when kernel is suspected to allocate a new page
  refresh_memory_map();

  uint32_t flags = *((uint32_t *)ctx->etc);

  // SOURCE
  if (flags & IO_SRC) {
    // TODO: maybe some logging, but for now this is just confusing
    // LOG_DEBUG("T%d: Found source: %s", ctx->tid, ctx->name.c_str());
  }

  // SINK
  if (flags & IO_SINK) {
    LOG_DEBUG("T%d: Found sink: %s", ctx->tid, ctx->name.c_str());

    // for strcmp like function based on cmp string
    if (ctx->name.find("cmp") != std::string::npos){
      char *dst = (char *)ctx->arg_val[0];
      char *src = (char *)ctx->arg_val[1];
      int taint_dst = 0;
      int taint_src = 0;
      if (tf_region_check((void *)dst, strlen(dst))){
        taint_dst = 1;
      }
      if (tf_region_check((void *)src, strlen(src))){
        taint_src = 1;
      }
      if (taint_src || taint_dst){
        logger.store_cmp_pre(TT_CMP, dst, src, taint_dst, taint_src);
        trace_cmp_start();
      }
    }

    // iterate over argument values
    for (size_t i = 0; i < ctx->arg_val.size(); i++) {
      tf_type_t type = tf_check_type(ctx->arg_val[i]);

      // pointer input values in the accessible
      // memory regions
      if (type == HEAP_PTR || type == STACK_PTR) {
        size_t len = tf_mem_get_size((void *)ctx->arg_val[i]);
        if (len > 0 && tf_region_check((void *)ctx->arg_val[i], len)) {
          LOG_ALERT("T%d: SINK %s touched tainted data at 0x%lx", ctx->tid, ctx->name.c_str(),
                    ctx->arg_val[i]);
          logger.store(TT_UNKNOWN, ctx);
        }
      }

      // mapped memory regions
      else if (type == MAPPED_PTR || type == LIB_PTR) {
        // TODO: probably should not fidget there, but data values are sometimes there
        // check for TS_ENVIRONMENT
        tf_region_check((void *)ctx->arg_val[i], 1);
      }

      // skip null values
      else if (type == NULL_PTR || type == UNKNOWN) {
        continue;
      }

      else {
        // check the smallest int storage value amount of bytes
        // to make sure to avoid false positives
        // TODO: get size from heuristics
        if (i < ctx->arg_addr.size() && ctx->arg_addr[i]) {
          tf_region_check((void *)ctx->arg_addr[i], sizeof(short));
        } else {
          LOG_WARN("T%d: Invalid arg_addr[%zu] for function %s", ctx->tid, i, ctx->name.c_str());
        }
      }
    }
  }
}

static void
generic_post(tf_hook_ctx_t *ctx) {
  if (!ctx) {
    LOG_ERROR("T%d: NULL context in generic_post", PIN_ThreadId());
    return;
  }

  // fetch the memory mapping
  // from /proc/self/maps
  // TODO: find a balance, when to call
  // maybe monitor memory usage and only refresh when kernel is suspected to allocate a new page
  refresh_memory_map();

  // get classification
  uint32_t flags = *((uint32_t *)ctx->etc);

  // SOURCE
  if (flags & IO_SRC) {
    LOG_DEBUG("T%d: Found source: %s", ctx->tid, ctx->name.c_str());

    // RETURN: suspect allocation if return value points to HEAP
    // suspect string return if points to the stack
    if (ctx->ret_val != 0) {

      // classify the return type
      tf_type_t ret_type = tf_check_type(ctx->ret_val);

      if (ret_type == HEAP_PTR) {

        size_t potential_size = 1;
        for (size_t i = 0; i < ctx->arg_val.size(); i++) {

          // TODO: use first now, come up with better
          // if we find a size argument
          if (tf_check_type(ctx->arg_val[i]) == SIZE_ARG) {
            potential_size = (size_t)ctx->arg_val[i];
            break;
          }
        }

        // register and taint memory region with sizearg
        // if found, if not, taint 1 byte TODO: do better
        tf_mem_register((void *)ctx->ret_val, potential_size);
        tf_region_taint((void *)ctx->ret_val, potential_size, TS_HEAP, 1);
        LOG_TAINT("T%d: Marked return value 0x%lx[%zu] as tainted for %s", ctx->tid, ctx->ret_val,
                  potential_size, ctx->name.c_str());

      }

      // THIS IS VERY JANKY, specific for glibc
      // strings or buffer, same method, or environment variables are
      // copied by __libc_start_main, but can be totally different in other libs
      // TODO: implement functionality for musl.c and later for other libraries
      else if (ret_type == STACK_PTR) {

        size_t potential_size = 1;
        for (size_t i = 0; i < ctx->arg_val.size(); i++) {

          // TODO: use first now, come up with better
          // if we find a size argument
          if (tf_check_type(ctx->arg_val[i]) == SIZE_ARG) {
            potential_size = (size_t)ctx->arg_val[i];
            break;
          }
        }

        // register and taint memory region
        tf_mem_register((void *)ctx->ret_val, potential_size);
        tf_region_taint((void *)ctx->ret_val, potential_size, TS_STACK, 1);
        LOG_TAINT("T%d: Marked return value 0x%lx[%zu] as tainted for %s", ctx->tid, ctx->ret_val,
                  potential_size, ctx->name.c_str());
      }

      else if (ret_type == INVALID_PTR) {
        LOG_WARN("T%d: Return value 0x%lx is invalid pointer - not tainting for %s", ctx->tid,
                 ctx->ret_val, ctx->name.c_str());
      }

      // TODO: this usually allocates memory internally
      // or just points to the data section that is on the readonly stack
      else if (ret_type == LIB_PTR || ret_type == MAPPED_PTR) {
        tf_region_taint((void *)ctx->ret_val, 1, TS_ENVIRONMENT, 1);
        LOG_TAINT("T%d: Return value 0x%lx points to library/mapped memory - monitoring for %s",
                  ctx->tid, ctx->ret_val, ctx->name.c_str());
      }

      else {
        // NUMERICAL VALUES
        // TODO: what do we do here? maybe propagate the return register to taint that??
        LOG_DEBUG("T%d: Return value 0x%ld is numerical value for %s, nothing to do for now",
                  ctx->tid, ctx->ret_val, ctx->name.c_str());
      }
    }

    // OUTPUT PARAMS: check if there were any pointers
    for (size_t i = 0; i < ctx->arg_val.size(); ++i) {

      ADDRINT arg = ctx->arg_val[i];
      tf_type_t arg_type = tf_check_type(arg);

      // if output pointer points to heap (or stack) <-unlikely
      if (arg_type == HEAP_PTR || arg_type == STACK_PTR) {
        size_t len = 0;

        // NAIVE APPROACH: find first size-like value in remaining arguments
        // since this is a common pattern in functions, its a good approximation
        for (size_t j = i + 1; j < ctx->arg_val.size(); ++j) {
          ADDRINT potential_size = ctx->arg_val[j];

          if (tf_check_type(potential_size) == SIZE_ARG) {
            len = potential_size;
            LOG_DEBUG("T%d: Using arg[%zu] = %zu as size for pointer arg[%zu] = 0x%lx in %s",
                      ctx->tid, j, len, i, arg, ctx->name.c_str());
            break;
          }
        }

        if (len > 0) {
          switch (arg_type) {

          case HEAP_PTR:
            tf_region_taint((void *)arg, len, TS_HEAP, 1);
            LOG_TAINT("T%d: Marked arg[%zu] = 0x%lx[%zu] as tainted on HEAP for %s", ctx->tid, i,
                      arg, len, ctx->name.c_str());
            break;

          case STACK_PTR:
            tf_region_taint((void *)arg, len, TS_ARGUMENT, 1);
            LOG_TAINT("T%d: Marked arg[%zu] = 0x%lx[%zu] as tainted on STACK for %s", ctx->tid, i,
                      arg, len, ctx->name.c_str());
            break;

          default:
            assert(0); //< unreachable
            break;
          }
        } else {
          LOG_WARN("T%d: Out param arg[%zu] = 0x%lx was not registered for %s (no size found)",
                   ctx->tid, i, arg, ctx->name.c_str());
        }
      }
    }
  }

  // SINK
  if (flags & IO_SINK) {
    // TODO: maybe some logging, but for now this is just confusing
    // LOG_DEBUG("T%d: Found sink: %s", ctx->tid, ctx->name.c_str());
  }
}

/*
 * Internal function registry
 */
using func_cb_t = void (*)(tf_hook_ctx_t *);
struct hook_t {
  sig_entry_t *sig;
  func_cb_t pre;
  func_cb_t post;
};

static std::map<std::string, hook_t> tf_func_registry;

void
tf_override_func(std::string name, func_cb_t pre, func_cb_t post) {
  auto it = tf_func_registry.find(name);
  if (it == tf_func_registry.end()) {
    LOG_WARN("Function %s is not yet registered", name.c_str());
    return;
  }

  tf_func_registry[name].pre = pre;
  tf_func_registry[name].post = post;
  LOG_INFO("Overridden callbacks for function: %s", name.c_str());
}

void
tf_register_func(sig_entry_t *sig, func_cb_t pre, func_cb_t post) {
  if (!sig) {
    LOG_ERROR("Cannot register function: NULL signature");
    return;
  }

  auto it = tf_func_registry.find(sig->name);
  if (it != tf_func_registry.end()) {
    LOG_WARN("Function %s already registered, skipping", sig->name.c_str());
    return;
  }
  tf_func_registry[sig->name] = hook_t{sig, pre, post};
  LOG_INFO("Registered function: %s", sig->name.c_str());
}

void
tf_register_all() {
  LOG_INFO("Registering all functions from signature table");
  for (sig_entry_t &s : tf_sig_table) {
    tf_register_func(&s, generic_pre, generic_post);
  }
  LOG_INFO("Finished registering %zu functions", tf_func_registry.size());
}

/*
 * Thread-local context for pre-post HANDLER communication
 */
struct tf_thread_ctx_t {
  vcpu_ctx_t vcpu;
  tf_hook_ctx_t func_ctx;
};

// Thread-local storage key
static TLS_KEY func_tls_key;

// --- Pin Instrumentation Callbacks ---
static VOID
tf_pre_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT ret_addr, UINT32 nargs,
               ADDRINT *arg0_addr, ADDRINT arg0_val, ADDRINT *arg1_addr, ADDRINT arg1_val,
               ADDRINT *arg2_addr, ADDRINT arg2_val, ADDRINT *arg3_addr, ADDRINT arg3_val,
               ADDRINT *arg4_addr, ADDRINT arg4_val, ADDRINT *arg5_addr, ADDRINT arg5_val) {

  // NOTE: no need to lock if symbols are initialized
  PIN_LockClient();
  std::string func_name = RTN_FindNameByAddress(func_addr);
  IMG img_addr = IMG_FindByAddress(ret_addr);
  bool is_from_main = IMG_Valid(img_addr) && IMG_IsMainExecutable(img_addr);
  PIN_UnlockClient();

  // skip if internal library call
  // TODO: smarter blacklisting
  if (!is_from_main) {
    PIN_SetThreadData(func_tls_key, NULL, tid);
    return;
  }

  // find the descriptor for func
  auto func = tf_func_registry.begin();
  for (; func != tf_func_registry.end(); ++func) {
    if (func_name.find(func->first) != std::string::npos)
      break;
  }

  // sanity check
  if (func == tf_func_registry.end()) {
    PIN_SetThreadData(func_tls_key, NULL, tid); // ensure TLS is cleared
    return;
  }

  tf_thread_ctx_t *thread_ctx = new tf_thread_ctx_t();
  if (!thread_ctx) {
    LOG_ERROR("T%d: Failed to allocate tf_thread_ctx_t for %s", tid, func_name.c_str());
    PIN_SetThreadData(func_tls_key, NULL, tid);
    return;
  }

  // Initialize the context
  // memset(thread_ctx, 0, sizeof(tf_thread_ctx_t));

  thread_ctx->func_ctx.name = func->first;
  thread_ctx->func_ctx.tid = tid;
  thread_ctx->func_ctx.func_addr = func_addr;
  thread_ctx->func_ctx.ret_val = 0;
  thread_ctx->func_ctx.etc = (uintptr_t)&(func->second.sig->flags); // hand over flags

  // clear args vectors before adding new arguments
  thread_ctx->func_ctx.arg_addr.clear();
  thread_ctx->func_ctx.arg_val.clear();

  // Validate nargs to prevent out-of-bounds access
  if (nargs > 6) {
    LOG_WARN("T%d: Function %s has %u args, but only 6 are supported", tid, func_name.c_str(),
             nargs);
    nargs = 6; // Cap at maximum supported
  }

  // add only the arguments the function expects
  if (nargs > 0) {
    thread_ctx->func_ctx.arg_addr.push_back(arg0_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg0_val);
  }
  if (nargs > 1) {
    thread_ctx->func_ctx.arg_addr.push_back(arg1_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg1_val);
  }
  if (nargs > 2) {
    thread_ctx->func_ctx.arg_addr.push_back(arg2_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg2_val);
  }
  if (nargs > 3) {
    thread_ctx->func_ctx.arg_addr.push_back(arg3_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg3_val);
  }
  if (nargs > 4) {
    thread_ctx->func_ctx.arg_addr.push_back(arg4_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg4_val);
  }
  if (nargs > 5) {
    thread_ctx->func_ctx.arg_addr.push_back(arg5_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg5_val);
  }

  PIN_SetThreadData(func_tls_key, thread_ctx, tid);

  // CALL the pre-hook callback if registered
  if (func->second.pre != nullptr) {
    func->second.pre(&(thread_ctx->func_ctx));
  }
}

static VOID
tf_post_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT ret_val) {
  tf_thread_ctx_t *thread_ctx = (tf_thread_ctx_t *)PIN_GetThreadData(func_tls_key, tid);

  if (thread_ctx != NULL) {
    thread_ctx->func_ctx.ret_val = ret_val;

    PIN_LockClient();
    std::string func_name = RTN_FindNameByAddress(func_addr);
    PIN_UnlockClient();

    // find the descriptor for func
    auto func = tf_func_registry.begin();
    for (; func != tf_func_registry.end(); ++func) {
      if (func_name.find(func->first) != std::string::npos)
        break;
    }

    // sanity check
    if (func == tf_func_registry.end()) {
      LOG_WARN("T%d: Function %s not found in registry during post-handler", tid,
               func_name.c_str());
      delete thread_ctx; // Prevent memory leak
      PIN_SetThreadData(func_tls_key, NULL, tid);
      return;
    }

    // CALL the post-hook callback if registered
    if (func->second.post) {
      func->second.post(&(thread_ctx->func_ctx));
    }

    delete thread_ctx;
  } else {
    LOG_WARN("T%d: No thread context found for function at 0x%lx", tid, func_addr);
  }

  PIN_SetThreadData(func_tls_key, NULL, tid);
}

using match_func = bool (*)(std::string rtn, std::string func);

static VOID
tf_instrument_rtn(
    RTN rtn, match_func cmp = [](std::string str1, std::string str2) {
      return str1.find(str2) != std::string::npos;
    }) {
  std::string func_name = RTN_Name(rtn);

  // invalid
  if (!RTN_Valid(rtn)) {
    LOG_ERROR("Attempted to instrument invalid routine: %s", func_name.c_str());
    return;
  } else {
    LOG_INFO("Instrumenting function: %s", func_name.c_str());
  }

  RTN_Open(rtn);

  // find the hook descriptor for this function
  hook_t hook = {nullptr, nullptr, nullptr};
  for (const auto &entry : tf_func_registry) {
    // important: partial matching
    // TODO: maybe sometimes aliases are completely different
    if (cmp(func_name, entry.first)) {
      hook = entry.second;
      break;
    }
  }

  if (hook.sig == nullptr) {
    LOG_WARN("No hook signature found for function: %s", func_name.c_str());
    RTN_Close(rtn);
    return;
  }

  if (hook.pre != nullptr) {
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)tf_pre_handler, IARG_THREAD_ID, IARG_CONTEXT,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_RETURN_IP, IARG_UINT32, hook.sig->nargs,
                   // hand over both address and value
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                   IARG_END);
  }

  if (hook.post != nullptr) {
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)tf_post_handler, IARG_THREAD_ID, IARG_CONTEXT,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
  }

  RTN_Close(rtn);
}

static VOID
tf_instrument_img(IMG img, VOID *lib) {
  // invalid
  if (!IMG_Valid(img)) {
    LOG_ERROR("Attempted to process invalid image");
    return;
  }

  // not the target library
  if (IMG_Name(img).find((const char *)lib) == std::string::npos) {
    return;
  }

  LOG_INFO("Processing image: %s", IMG_Name(img).c_str());
  size_t instrumented_count = 0;

  for (const auto &kv : tf_func_registry) {
    std::string func_name = kv.first;

    RTN rtn = RTN_FindByName(img, func_name.c_str());
    ADDRINT addr = RTN_Address(rtn);

    // Look for symbol aliases at the same address
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
      if (SYM_Address(sym) == addr) {
        // override the hooked name found in the lib
        // with the first function on the same address
        rtn = RTN_FindByName(img, SYM_Name(sym).c_str());
        break;
      }
    }

    // invalid symbol (e.g. inline)
    if (!RTN_Valid(rtn)) {
      continue;
    }

    // instrument
    tf_instrument_rtn(rtn);
    instrumented_count++;
  }

  LOG_INFO("Instrumented %zu functions in image: %s", instrumented_count, IMG_Name(img).c_str());
}

static VOID
fini(INT32 code, VOID *v) {
  LOG_INFO("Application finished with code %d. Cleaning up function registry.", code);
  logger.save_buffers();
  tf_func_registry.clear();
  tf_mem_die();
  libdft_die();
  LOG_INFO("Cleanup completed.");
}

#endif // !TF_TOOLS_H
