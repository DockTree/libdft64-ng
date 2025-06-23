#include <string>

#include "pin.H"

#define DEBUG_TAINT
#define TAINT_IMPLEMENTATION
#include "memmng.h"
#include "taint.h"

// register-passed args
#define FUNCTION_ARG_LIMIT 6

enum io_flag_t { IO_SRC = 1 << 0, IO_SINK = 1 << 1 };
struct sig_entry_t {
  const char *name;
  uint32_t io_flags; // IO_SRC | IO_SINK | …
  uint32_t nargs;
  int8_t taint_map[FUNCTION_ARG_LIMIT]; // -1 = ignore, otherwise argidx
};

/* header that *uses* the table */
#define TF_SIG_ENTRY(name, flags, argc, ...) {name, flags, argc, {__VA_ARGS__}},
const sig_entry_t tf_sig_table[] = {
//#include "tf_std_sig.h"
};
#undef TF_SIG_ENTRY

// thread-local storage key
static TLS_KEY func_tls_key;

ADDRINT low_address = 0;
ADDRINT high_address = 0;
ADDRINT call_addr = 0;

ins_desc_t ins_desc[XED_ICLASS_LAST];

/*
 * Exposed hook context
 */
typedef struct {
  std::string name;
  THREADID tid;
  ADDRINT address;
  std::vector<ADDRINT> args;
  ADDRINT retval;
  uintptr_t etc;
} tf_hook_ctx_t;

#include "logger.h"
Logger logger;

/*
 * Thread-local context for pre-post hook communication
 */
typedef struct {
  vcpu_ctx_t vcpu;
  tf_hook_ctx_t func_ctx;
} tf_thread_ctx_t;

/*
 * Function registry
 */
using func_cb_t = void (*)(tf_hook_ctx_t *);
struct hook_t {
  UINT32 nargs;
  func_cb_t pre;
  func_cb_t post;
};
static std::map<std::string, hook_t> tf_func_registry;

int
tf_register_func(std::string func_name, UINT32 nargs, func_cb_t pre, func_cb_t post) {
  tf_func_registry[func_name] = hook_t{nargs, pre, post};
  fprintf(stdout, "[INF] Registered hook for function: %s\n", func_name.c_str());
  return 1;
}

// --- API Hook Callbacks ---
static void
pre_system_hook(tf_hook_ctx_t *ctx) {
  const char *command = (const char *)ctx->args[0];
  size_t size = tf_mem_get_size((void *)ctx->args[0]);
  if (command && tf_region_check((void *)command, size)) {
    fprintf(stdout, "[SNK] T%d: system(command=\"%s\") argument is tainted.\n", ctx->tid, command);
    logger.store(TT_EXEC, ctx);
  } else {
    fprintf(stdout, "[SNK] T%d: system(command=\"%s\") no taint found.\n", ctx->tid,
            command ? command : "NULL");
  }
}

static void
pre_malloc_hook(tf_hook_ctx_t *ctx) {
  size_t size = (size_t)ctx->args[0];
  fprintf(stdout, "[PRE] T%d: pre_malloc(size=%lu) at addr=0x%lx.\n", ctx->tid, (unsigned long)size,
          (unsigned long)ctx->address);
}

static void
post_malloc_hook(tf_hook_ctx_t *ctx) {
  uintptr_t ptr = (uintptr_t)(void *)ctx->retval;
  size_t size = (size_t)ctx->args[0]; // retrieve size

  fprintf(stdout, "[PST] T%d: post_malloc(ptr=0x%lx, size=%lu) from call at addr=0x%lx.\n",
          ctx->tid, ptr, (unsigned long)size, (unsigned long)ctx->address);

  if (ptr && (size > 0)) {
    tf_mem_register((void *)ptr, size);             //< register to memmng
    tf_region_taint((void *)ptr, size, TS_HEAP, 1); //< taint region
  }
}


static void
trace_uaf(INS ins);

static void
trace_uaf_start() {

  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_MOV;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_uaf;
}

static void
trace_uaf_stop() {

  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_MOV;

  if (unlikely(ins_desc[ins_indx].pre == trace_uaf))
    ins_desc[ins_indx].pre = NULL;
}

static void
uaf(ADDRINT dst) {
  // printf("memory: %lx\n", dst);
  if (tag_uaf_getb(dst)) {
    logger.store_ins(TT_UAF, dst);
    trace_uaf_stop();
  }
}

static void
unknown_func(ADDRINT a0, ADDRINT a1, ADDRINT a2, ADDRINT a3, ADDRINT a4, ADDRINT a5){
  tf_hook_ctx_t *func_ctx = (tf_hook_ctx_t*)malloc(sizeof(tf_hook_ctx_t));
  std::vector<ADDRINT> args_ = {a0, a1, a2, a3, a4, a5};
  func_ctx->address = call_addr;
  func_ctx->args = args_;
  logger.store(TT_UNKNOWN, func_ctx);
}

static void
trace_uaf(INS ins) {
  if (INS_OperandIsMemory(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)uaf, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA,
                   IARG_END);
  }
}

static void
trace_call(INS ins) {
  if (INS_IsDirectControlFlow(ins)){
    call_addr = INS_DirectBranchOrCallTargetAddress(ins);
    // fprintf(stdout, "[INF] call_addr: %ld\n", call_addr);
    if (call_addr < low_address){
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)unknown_func, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_FUNCARG_CALLSITE_VALUE, 2, IARG_FUNCARG_CALLSITE_VALUE, 3, IARG_FUNCARG_CALLSITE_VALUE, 4, IARG_FUNCARG_CALLSITE_VALUE, 5, 
                      IARG_END);
    }
  }
  // TODO solve indirect call such as call rbx
}

static void
trace_ret(INS ins) {
  trace_uaf_stop();
}

static void
trace_call_start(){
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_CALL_NEAR;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_call;
}

static void
trace_ret_start(){
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_RET_NEAR;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_ret;
}

static void
pre_free_hook(tf_hook_ctx_t *ctx) {
  uintptr_t addr = (uintptr_t)(void *)ctx->args[0];
  size_t size_to_clear = tf_mem_get_size((void *)addr); //< fetch from memmng
  if (addr) {
    tf_region_clear((void *)addr, size_to_clear);
    tf_mem_unregister((void *)addr);
    fprintf(stdout, "[INF] T%d: free(ptr=0x%lx), cleared %zu bytes of taint.\n", ctx->tid,
            (unsigned long)addr, size_to_clear);
    for (uintptr_t i = addr; i < addr + (unsigned int)size_to_clear; i++) {
      tag_uaf_setb(addr, 0x26); // for uaf
    }
  } else {
    fprintf(stdout, "[INF] T%d: free(ptr=NULL) called.\n", ctx->tid);
  }
}

static void
post_free_hook(tf_hook_ctx_t *ctx) {
  trace_uaf_start();
}

// --- Pin Instrumentation Callbacks ---
static VOID
tf_pre_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT return_ip, UINT32 nargs,
               ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5) {

  // NOTE: no need to lock if symbols are initialized
  PIN_LockClient();
  std::string func_name = RTN_FindNameByAddress(func_addr);
  IMG img_ip = IMG_FindByAddress(return_ip);
  bool is_from_main = IMG_Valid(img_ip) && IMG_IsMainExecutable(img_ip);
  PIN_UnlockClient();

  // skip if internal library call
  // TODO: smarter blacklisting
  if (!is_from_main) {
    PIN_SetThreadData(func_tls_key, NULL, tid);
    return;
  }

  // find the descriptor for func
  auto it = tf_func_registry.begin();
  for (; it != tf_func_registry.end(); ++it) {
    if (func_name.find(it->first) != std::string::npos)
      break;
  }

  // sanity check
  if (it == tf_func_registry.end()) {
    PIN_SetThreadData(func_tls_key, NULL, tid); // ensure TLS is cleared
    return;
  }

  tf_thread_ctx_t *thread_ctx = new tf_thread_ctx_t();
  if (!thread_ctx) {
    fprintf(stderr, "[ERR] T%d: Failed to allocate tf_thread_ctx_t for %s\n", tid,
            func_name.c_str());
    PIN_SetThreadData(func_tls_key, NULL, tid);
    return;
  }

  thread_ctx->func_ctx.name = it->first;
  thread_ctx->func_ctx.tid = tid;
  thread_ctx->func_ctx.address = func_addr;
  thread_ctx->func_ctx.retval = 0;
  thread_ctx->func_ctx.etc = 0;

  // Clear args vector before adding new arguments
  thread_ctx->func_ctx.args.clear();

  // Only include the number of arguments the function actually expects
  UINT32 actual_nargs = it->second.nargs;
  if (actual_nargs > FUNCTION_ARG_LIMIT) {
    fprintf(stderr,
            "[WRN] Function %s has more than %d arguments. Only the first %d are captured.\n",
            func_name.c_str(), FUNCTION_ARG_LIMIT, FUNCTION_ARG_LIMIT);
    actual_nargs = FUNCTION_ARG_LIMIT;
  }

  // Add only the arguments the function expects
  if (actual_nargs > 0)
    thread_ctx->func_ctx.args.push_back(arg0);
  if (actual_nargs > 1)
    thread_ctx->func_ctx.args.push_back(arg1);
  if (actual_nargs > 2)
    thread_ctx->func_ctx.args.push_back(arg2);
  if (actual_nargs > 3)
    thread_ctx->func_ctx.args.push_back(arg3);
  if (actual_nargs > 4)
    thread_ctx->func_ctx.args.push_back(arg4);
  if (actual_nargs > 5)
    thread_ctx->func_ctx.args.push_back(arg5);

  PIN_SetThreadData(func_tls_key, thread_ctx, tid);

  // CALL the pre-hook callback if registered
  if (it->second.pre != nullptr) {
    it->second.pre(&(thread_ctx->func_ctx));
  }
}

static VOID
tf_post_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT ret_val) {
  tf_thread_ctx_t *thread_ctx = (tf_thread_ctx_t *)PIN_GetThreadData(func_tls_key, tid);

  if (thread_ctx != NULL) {
    thread_ctx->func_ctx.retval = ret_val;

    PIN_LockClient();
    std::string func_name = RTN_FindNameByAddress(func_addr);
    PIN_UnlockClient();

    // find the descriptor for func
    auto it = tf_func_registry.begin();
    for (; it != tf_func_registry.end(); ++it) {
      if (func_name.find(it->first) != std::string::npos)
        break;
    }

    // sanity check
    if (it == tf_func_registry.end()) {
      delete thread_ctx; // Prevent memory leak
      PIN_SetThreadData(func_tls_key, NULL, tid);
      return;
    }

    if (it->second.post) {
      it->second.post(&(thread_ctx->func_ctx));
    }

    delete thread_ctx;
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
    fprintf(stderr, "[ERR] Attempted to instrument invalid routine: %s\n", func_name.c_str());
    return;
  } else {
    fprintf(stdout, "[INF] Instrumenting function: %s\n", func_name.c_str());
  }

  RTN_Open(rtn);

  // find the hook descriptor for this function
  hook_t hook = {0, nullptr, nullptr};
  for (const auto &entry : tf_func_registry) {
    // important: partial matching
    // TODO: maybe sometimes aliases are completely different
    if (cmp(func_name, entry.first)) {
      hook = entry.second;
      break;
    }
  }

  if (hook.pre != nullptr) {
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)tf_pre_handler, IARG_THREAD_ID, IARG_CONTEXT,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_RETURN_IP, IARG_UINT32, hook.nargs,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_END);
  }

  if (hook.post != nullptr) {
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)tf_post_handler, IARG_THREAD_ID, IARG_CONTEXT,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
  }

  RTN_Close(rtn);
}

/*typedef struct {*/
/*  const char *lib;*/
/*  match_func cmp;*/
/*} probe_ctx_t;*/

void InstImage(IMG img, void* v)
{
  if (low_address != 0) return;// can only get got

  SEC sec = IMG_SecHead(img);
  while (SEC_Type(sec) != SEC_TYPE_GOT){
    sec = SEC_Next(sec);
    if (sec == SEC_Invalid()){
      break;
    }
  }

  low_address = SEC_Address(sec);
  high_address = low_address + SEC_Size(sec);

}


static VOID
tf_instrument_img(IMG img, VOID *lib) {
  /*probe_ctx_t *ctx = (probe_ctx_t *)pc;*/

  // not the target library
  if (IMG_Name(img).find((const char *)lib) == std::string::npos) {
    return;
  }

  // invalid
  if (!IMG_Valid(img)) {
    fprintf(stderr, "[ERR] Attempted to process invalid image\n");
    return;
  }

  fprintf(stdout, "[INF] Processing image: %s\n", IMG_Name(img).c_str());
  for (const auto &kv : tf_func_registry) {
    std::string func_name = kv.first;

    RTN rtn = RTN_FindByName(img, func_name.c_str());
    ADDRINT addr = RTN_Address(rtn);
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
      if (SYM_Address(sym) == addr) {
        // override the hooked name found in the lib
        // with the first funcion on the same address
        rtn = RTN_FindByName(img, SYM_Name(sym).c_str());
      }
    }

    // invalid symbol (e.g. inline)
    if (!RTN_Valid(rtn)) {
      continue;
    }

    // instrument
    tf_instrument_rtn(rtn);
  }
}

static VOID
fini(INT32 code, VOID *v) {
  logger.save_buffers();
  fprintf(stdout, "[INF] Application finished. Cleaning up function registry.\n");
  tf_func_registry.clear();
  tf_mem_die();
  libdft_die();
}

int
main(int argc, char **argv) {

  /*probe_ctx_t pc = {"libc", (match_func)[](std::string str1, std::string str2) {*/
  /*                    return (str1.find(str2) != std::string::npos);*/
  /*                  }};*/

  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) {
    fprintf(stderr, "[ERR] PIN_Init failed: %s\n", PIN_ToolFullPath());
    goto err;
  }

  func_tls_key = PIN_CreateThreadDataKey(NULL); // Pass destructor if needed
  if (func_tls_key == INVALID_TLS_KEY) {
    fprintf(stderr, "[ERR] Cannot allocate TLS key.\n");
    goto err;
  }

  if (libdft_init() != 0) {
    fprintf(stderr, "[ERR] Failed to initialize libdft.\n");
    goto err;
  }

  // init mem
  tf_mem_init();

  // register hooks
  tf_register_func("malloc", 1, pre_malloc_hook, post_malloc_hook);
  tf_register_func("system", 1, pre_system_hook, nullptr);
  tf_register_func("free", 1, pre_free_hook, post_free_hook);

  IMG_AddInstrumentFunction(InstImage, 0);

  IMG_AddInstrumentFunction(tf_instrument_img, (VOID *)"libc");

  // detect call ins for external lib call
  trace_call_start();
  //ret ins for uaf trace stop point
  trace_ret_start();

  // register Fini function to be called when the application exits
  PIN_AddFiniFunction(fini, 0);

  fprintf(stdout, "[INF] Starting program instrumentation...\n");
  PIN_StartProgram();

  return EXIT_SUCCESS;

err:
  fprintf(stderr, "[ERR] Tool initialization failed. Exiting.\n");
  return EXIT_FAILURE;
}

// TODO: instrument GOT/PLT or detect call ins for external lib call detection
// NOTE: GOT and PLT are for some reason completely empty in the test scenario
// TODO: hook libc
// TODO: try other libs
// TODO: parameter type info from signature in handlers or hooks
