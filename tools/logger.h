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
  LogBuf exec_buf;
  LogBuf uaf_buf;
  LogBuf bof_buf;
  LogBuf unknown_buf;
  std::map<u64, u32> order_map;


public:
  Logger(){};
  ~Logger(){};
  void store(taint_type_t type, tf_hook_ctx_t *ctx){
    //fprintf(stdout, "[LOGGER] start store\n");
    if (type == TT_EXEC){// command injection 
      ADDRINT hash = ctx->address;
      u32 size = 0;
      for (int i = 0; i < (int)ctx->args.size(); i++){
        // hash ^= ctx->args[i];// identify unique
        size += strlen((char *)ctx->args[i]);
        //fprintf(stdout, "args size: %d\n", size);
      }
      char args[size];
      memset(args, 0, size);
      if (order_map.count(hash) == 0 && size > 0) {
        for (int i = 0; i< (int)ctx->args.size(); i++){
          strcat(args,(char *)ctx->args[i]);
        }
        fprintf(stdout, "taint_arg: %s\n", args);
        order_map.insert(std::pair<u64, u32>(hash, 1));
        //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
        exec_buf.push_bytes((char *)&size, 4);
        exec_buf.push_bytes(args, size);
        end_exec += size + 4;
        num_exec += 1;
      }
    }
    else if (type == TT_BOF)// buffer overflow
    {
      ADDRINT hash = ctx->address;
      u32 size = 0;
      for (int i = 0; i < (int)ctx->args.size(); i++){
        // hash ^= ctx->args[i];// identify unique
        size += strlen((char *)ctx->args[i]);
        //fprintf(stdout, "args size: %d\n", size);
      }
      char args[size];
      memset(args, 0, size);
      if (order_map.count(hash) == 0 && size > 0) {
        for (int i = 0; i< (int)ctx->args.size(); i++){
          strcat(args,(char *)ctx->args[i]);
        }
        fprintf(stdout, "taint_arg: %s\n", args);
        order_map.insert(std::pair<u64, u32>(hash, 1));
        //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
        exec_buf.push_bytes((char *)&size, 4);
        exec_buf.push_bytes(args, size);
        end_bof += size + 4;
        num_bof += 1;
      }
    }
    else if (type == TT_UNKNOWN){
      return;
      // TODO handle different type parameters
      // ADDRINT hash = ctx->address;
      // u32 size = 0;
      // for (int i = 0; i < (int)ctx->args.size(); i++){
      //   // hash ^= ctx->args[i];// identify unique
      //     size += strlen((char *)ctx->args[i]);
      //   //fprintf(stdout, "args size: %d\n", size);
      // }
      // char args[size];
      // memset(args, 0, size);
      // if (order_map.count(hash) == 0 && size > 0) {
      //   for (int i = 0; i< (int)ctx->args.size(); i++){
      //     strcat(args,(char *)ctx->args[i]);
      //   }
      //   fprintf(stdout, "taint_arg: %s\n", args);
      //   order_map.insert(std::pair<u64, u32>(hash, 1));
      //   //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
      //   unknown_buf.push_bytes((char *)&size, 4);
      //   unknown_buf.push_bytes(args, size);
      //   num_unknown += 1;
      //}
    }
    
  }

  void store_ins(taint_type_t type, ADDRINT dst){
    num_uaf = 1;
    uaf_buf.push_bytes((char *)&dst, 8);
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

    exec_buf.write_file(out_f);
    bof_buf.write_file(out_f);
    

    if (out_f) {
      fclose(out_f);
      out_f = NULL;
    }
  }
};

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

#endif