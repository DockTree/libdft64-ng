#ifndef LOGGER_H
#define LOGGER_H

#include "libdft_api.h"
#include <set>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

#define TRACK_COND_OUTPUT_VAR "ANGORA_TRACK_OUTPUT"

#define BUF_LEN (2 << 16)

typedef enum {
  TT_EXEC = 0,        //< command injection.
  TT_UAF = 1, //use after free
  TT_BOF = 2, // buffer overflow
  TT_UNKNOWN = 3, // unknown
  TT_CMP = 4,
} taint_type_t;

struct CondStmt {
  u32 taint_type;
  u32 size;
};

class LogBuf {
private:
  char *buffer;
  size_t cap;
  size_t len;

public:
  void push_bytes(char *bytes, std::size_t size) {
    if (size > 0 && bytes) {
      size_t next = len + size;
      if (next > cap) {
        cap *= 2;
        buffer = (char *)realloc(buffer, cap);
      }
      memcpy(buffer + len, bytes, size);
      len = len + size;
    }
  };

  void insert_bytes(char *bytes, std::size_t size) {
    memset(buffer, 0, len);
    if (size > 0 && bytes) {
      size_t next = size;
      if (next > cap) {
        cap *= 2;
        buffer = (char *)realloc(buffer, cap);
      }
      memcpy(buffer, bytes, size);
      len = size;
    }
  };

  int read(int size){
    return (int)*(buffer+size);
  }

  char* read_all(){
    return buffer;
  }

  int cmp(int off1, int off2, int len){
    return strncmp(buffer+off1, buffer+off2, len);
  }

  void write_file(FILE *out_f) {
    if (!out_f || len == 0)
      return;
    int nr = fwrite(buffer, len, 1, out_f);
    if (nr < 1) {
      fprintf(stderr, "fail to write file %d %lu\n", nr, len);
      exit(1);
    }
  };

  LogBuf() {
    cap = BUF_LEN;
    buffer = (char *)malloc(cap);
    len = 0;
  };
  ~LogBuf() { free(buffer); }
};

class Logger {
private:
  u32 num_exec = 0;
  u32 end_exec = 0;
  u32 num_uaf = 0;
  u32 num_bof = 0;
  u32 end_bof = 0;
  u32 num_unknown = 0;
  u32 end_unknown = 0;
  u32 num_cmp = 0;
  LogBuf exec_buf;
  LogBuf uaf_buf;
  LogBuf bof_buf;
  LogBuf unknown_buf;
  LogBuf cmp_buf;
  LogBuf cmp_buf_pre;
  uint64_t cmp_addr = 0;
  int cmp_res = -1;
  int tag = 0;
  std::map<u64, u32> order_map;
  std::vector<unsigned long> total_start, total_end;


public:
  Logger(){
    FILE *fp = fopen("/proc/self/maps", "r");
    unsigned long start, end;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
      if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
        total_start.push_back(start);
        total_end.push_back(end);
      }
    }
    fclose(fp);
    uint64_t k;
    uint32_t v;
    fp = fopen("./order_map", "r");
    if (fp != NULL){
      while(fgets(line, sizeof(line), fp)){
        if (sscanf(line, "%ld-%d", &k, &v) == 2) {
          order_map[k] = v;
        }
      }
    }
  };
  ~Logger(){};
  void store(taint_type_t type, tf_hook_ctx_t *ctx){
    //fprintf(stdout, "[LOGGER] start store\n");
    if (type == TT_EXEC){// command injection 
      ADDRINT hash = ctx->func_addr;
      u32 size = 0;
      for (int i = 0; i < (int)ctx->arg_val.size(); i++){
        // hash ^= ctx->args[i];// identify unique
        size += strlen((char *)ctx->arg_val[i]);
        //fprintf(stdout, "args size: %d\n", size);
      }
      char args[size];
      memset(args, 0, size);
      if (order_map.count(hash) == 0 && size > 0) {
        for (int i = 0; i< (int)ctx->arg_val.size(); i++){
          strcat(args,(char *)ctx->arg_val[i]);
        }
        fprintf(stdout, "taint_arg: %s\n", args);
        order_map.insert(std::pair<u64, u32>(hash, 1));
        //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
        if (size > 0){
          exec_buf.push_bytes((char *)&size, 4);
          exec_buf.push_bytes(args, size);
          end_exec += size + 4;
          num_exec += 1;
        }
      }
    }
    else if (type == TT_BOF)// buffer overflow
    {
      ADDRINT hash = ctx->func_addr;
      u32 size = 0;
      for (int i = 0; i < (int)ctx->arg_val.size(); i++){
        // hash ^= ctx->args[i];// identify unique
        size += strlen((char *)ctx->arg_val[i]);
        //fprintf(stdout, "args size: %d\n", size);
      }
      char args[size];
      memset(args, 0, size);
      if (order_map.count(hash) == 0 && size > 0) {
        for (int i = 0; i< (int)ctx->arg_val.size(); i++){
          strcat(args,(char *)ctx->arg_val[i]);
        }
        fprintf(stdout, "taint_arg: %s\n", args);
        order_map.insert(std::pair<u64, u32>(hash, 1));
        //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
        if (size > 0){
          exec_buf.push_bytes((char *)&size, 4);
          exec_buf.push_bytes(args, size);
          end_bof += size + 4;
          num_bof += 1;
        }
      }
    }
    else if (type == TT_UNKNOWN){
      // TODO handle different type parameters
      ADDRINT hash = ctx->func_addr;
      u32 size = 0;
      for (int i = 0; i < (int)ctx->arg_val.size(); i++){
        // hash ^= ctx->args[i];// identify unique
        int j = 0;
        while(ctx->arg_val[i] >= total_end[j] && j < (int)(total_end.size()-1)){
          j++;
        }
        if (ctx->arg_val[i] >= total_start[j] && ctx->arg_val[i] <= total_end[j] && (int)ctx->arg_val[i] > 0) {
          size += strlen((char *)ctx->arg_val[i]);
        }
        // fprintf(stdout, "args size: %d\n", size);
      }
      char args[size];
      memset(args, 0, size);
      if (order_map.count(hash) == 0 && size > 0) {
        for (int i = 0; i< (int)ctx->arg_val.size(); i++){
          int j = 0;
          while(ctx->arg_val[i] >= total_end[j] && j < (int)(total_end.size()-1)){
            j++;
          }
          if (ctx->arg_val[i] >= total_start[j] && ctx->arg_val[i] <= total_end[j] && (int)ctx->arg_val[i] > 0) {
            strcat(args,(char *)ctx->arg_val[i]);
          }
        }
        order_map.insert(std::pair<u64, u32>(hash, 1));
        //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
        if(size > 0){
          unknown_buf.push_bytes((char *)&size, 4);
          unknown_buf.push_bytes(args, size);
          end_unknown += size + 4;
          num_unknown += 1;
        }
      }
    }
    
  }

  void store_ins(taint_type_t type, ADDRINT dst){
    if (type == TT_UAF && order_map.count(dst) == 0 && num_uaf == 0){
      num_uaf = 1;
      uaf_buf.push_bytes((char *)&dst, 8);
    }
  }

  void store_cmp_ins(taint_type_t type, ADDRINT addr){
    auto result = order_map.find(addr);
    tag = result->second;
    int len_dst = cmp_buf_pre.read(4);
    int len_src = cmp_buf_pre.read(4+len_dst);
    int len = len_dst;
    if (len_src < len){
      len = len_src;
    }
    int res = cmp_buf_pre.cmp(4, 8+len_dst, len);
    if(order_map.count(addr)){
      if (tag != 2 && tag != res){
        char *buf = cmp_buf_pre.read_all();
        cmp_buf.insert_bytes(buf, strlen(buf));
        cmp_addr = addr;
        cmp_res = res;
        num_cmp = 1;
        // order_map.erase(addr);
        // order_map.insert(std::pair<u64, u32>(addr, 2));
      }
    }
    else{
      char *buf = cmp_buf_pre.read_all();
      cmp_buf.insert_bytes(buf, strlen(buf));
      cmp_addr = addr;
      cmp_res = res;
      // order_map.insert(std::pair<u64, u32>(addr, res));
      num_cmp = 1;
    }
  }

  void save(){
    if(order_map.count(cmp_addr)){
      if (tag != 2 && tag != cmp_res){
        order_map.erase(cmp_addr);
        order_map.insert(std::pair<u64, u32>(cmp_addr, 2));
      }
    }
    else{
      order_map.insert(std::pair<u64, u32>(cmp_addr, cmp_res));
    }
    FILE *fp = fopen("./order_map", "w");
    if (fp != NULL){
      for (auto it = order_map.begin(); it != order_map.end(); ++it){
        fprintf(fp, "%ld-%d\n", it->first, it->second);
      }
    }
  }

  void store_cmp_pre(taint_type_t type, char *dst, char *src, int taint_dst, int taint_src){
    int len_dst = strlen(dst);
    int len_src = strlen(src);
    cmp_buf_pre.insert_bytes((char *)&len_dst, 4);
    cmp_buf_pre.push_bytes(dst, strlen(dst));
    cmp_buf_pre.push_bytes((char *)&len_src, 4);
    cmp_buf_pre.push_bytes(src, strlen(src));
    cmp_buf_pre.push_bytes((char *)&taint_dst, 1);
    cmp_buf_pre.push_bytes((char *)&taint_src, 1);
    fprintf(stdout, "strcmp: %s\n", cmp_buf_pre.read_all());
  }

  void save_buffers() {
    FILE *out_f = NULL;
    char *track_file = getenv(TRACK_COND_OUTPUT_VAR);
    if (track_file) {
      out_f = fopen(track_file, "w");
    } else {
      out_f = fopen("track.out", "w");
    }

    fwrite(&num_uaf, 4, 1, out_f);

    if (num_uaf == 1){
      uaf_buf.write_file(out_f);
    }

    fwrite(&num_exec, 4, 1, out_f);
    fwrite(&end_exec, 4, 1, out_f);
    fwrite(&num_bof, 4, 1, out_f);
    fwrite(&end_bof, 4, 1, out_f);
    fwrite(&num_unknown, 4, 1, out_f);
    fwrite(&end_unknown, 4, 1, out_f);

    exec_buf.write_file(out_f);
    bof_buf.write_file(out_f);
    unknown_buf.write_file(out_f);
    fwrite(&num_cmp, 4, 1, out_f);
    cmp_buf.write_file(out_f);
    fprintf(stdout, "cmp_buf: %s\n", cmp_buf_pre.read_all());
    save();
    

    if (out_f) {
      fclose(out_f);
      out_f = NULL;
    }
  }
};

static Logger logger;

// uaf taint map
tag_dir_t uaf_dir;

inline void tag_uaf_setb(ADDRINT addr, tag_t const &tag) {
  tag_dir_t &dir = uaf_dir;
  if (addr > 0x7fffffffffff) {
    return;
  }
  // LOG("Setting tag "+hexstr(addr)+"\n");
  if (dir.table[VIRT2PAGETABLE(addr)] == NULL) {
    //  LOG("No tag table for "+hexstr(addr)+" allocating new table\n");
#ifndef _WIN32
    tag_table_t *new_table = new (std::nothrow) tag_table_t();
#else // _WIN32
    tag_table_t *new_table = new tag_table_t();
#endif
    if (new_table == NULL) {
      LOG("Failed to allocate tag table!\n");
      libdft_die();
    }
    dir.table[VIRT2PAGETABLE(addr)] = new_table;
  }

  tag_table_t *table = dir.table[VIRT2PAGETABLE(addr)];
  if ((*table).page[VIRT2PAGE(addr)] == NULL) {
    //    LOG("No tag page for "+hexstr(addr)+" allocating new page\n");
#ifndef _WIN32
    tag_page_t *new_page = new (std::nothrow) tag_page_t();
#else // _WIN32
    tag_page_t *new_page = new tag_page_t();
#endif
    if (new_page == NULL) {
      LOG("Failed to allocate tag page!\n");
      libdft_die();
    }
    std::fill(new_page->tag, new_page->tag + PAGE_SIZE,
              tag_traits<tag_t>::cleared_val);
    (*table).page[VIRT2PAGE(addr)] = new_page;
  }

  tag_page_t *page = (*table).page[VIRT2PAGE(addr)];
  (*page).tag[VIRT2OFFSET(addr)] = tag;
  /*
  if (!tag_is_empty(tag)) {
    LOGD("[!]Writing tag for %p \n", (void *)addr);
  }
  */
}

inline tag_t const *tag_uaf_getb(ADDRINT addr) {
  tag_dir_t const &dir = uaf_dir;
  if (addr > 0x7fffffffffff) {
    return NULL;
  }
  if (dir.table[VIRT2PAGETABLE(addr)]) {
    tag_table_t *table = dir.table[VIRT2PAGETABLE(addr)];
    if ((*table).page[VIRT2PAGE(addr)]) {
      tag_page_t *page = (*table).page[VIRT2PAGE(addr)];
      if (page != NULL)
        return &(*page).tag[VIRT2OFFSET(addr)];
    }
  }
  return &tag_traits<tag_t>::cleared_val;
}

ins_desc_t ins_desc[XED_ICLASS_LAST];

void
trace_uaf(INS ins);// actual trace for logging

static void trace_ret_start();

void
trace_uaf_start() {// a start function to implement trace uaf
  xed_iclass_enum_t ins_indx;
  ins_indx = XED_ICLASS_MOV;
  if (unlikely(ins_desc[ins_indx].pre == NULL)){
    ins_desc[ins_indx].pre = trace_uaf;
    trace_ret_start();
  }
}

void
trace_uaf_stop() {// a stop function to stop trace
  xed_iclass_enum_t ins_indx;
  ins_indx = XED_ICLASS_MOV;
  if (unlikely(ins_desc[ins_indx].pre == trace_uaf))
    ins_desc[ins_indx].pre = NULL;
}

void
uaf(ADDRINT dst) {// check taint and log
  // printf("memory: %lx\n", dst);
  if (tag_uaf_getb(dst)) {
    logger.store_ins(TT_UAF, dst);
    trace_uaf_stop();
  }
}

void
trace_uaf(INS ins) {// call uaf to trace
  if (INS_OperandIsMemory(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)uaf, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA,
                   IARG_END);
  }
}

static void trace_cmp(INS ins);

static void
trace_cmp_stop(){// a stop function for stopping trace cmp
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_CMP;

  if (unlikely(ins_desc[ins_indx].pre == trace_cmp))
    ins_desc[ins_indx].pre = NULL;
}

static void
trace_cmp(INS ins){//log cmp instruction address
  if (INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
    ADDRINT addr = INS_Address(ins);
    logger.store_cmp_ins(TT_CMP, addr);
  }
  trace_cmp_stop();
}

static void
trace_cmp_start(){// start trace cmp
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_CMP;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_cmp;
}

static void
trace_ret(INS ins) {// after return, stop tracing uaf to reduce overload
  trace_uaf_stop();
}

static void
trace_ret_start(){// start tracing ret
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_RET_NEAR;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_ret;
}

#endif