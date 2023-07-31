#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <sys/shm.h>
#include "config.h"
#include "debug.h"
#include "errno.h"
#include "sys/wait.h"
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include "include/export.h"
#include "types.h"
#include "alloc-inl.h"
#include <openssl/md5.h>
#include <time.h>
#include <sys/time.h>

extern int errno;



/*************************
 * NoDrop Ioctl Part *
 *************************/

int device_fd;



/*************************
 * Debugging Part *
 *************************/

#ifdef CODE_PATH
#define LOGPATH CODE_PATH "/logs/temp.txt"
#define LOGFILE CODE_PATH "/logs/logging.txt"
#else
#define LOGPATH "./logs/temp.txt"
#define LOGFILE "./logs/logging.txt"
#endif 

// some debugging parts to record important infomation
#define LOGWRITE_BEGIN(x...) do { \
    FILE * logf = fopen(LOGFILE, "w+"); \
    fprintf(logf, x);\
    fprintf(logf, "\n");\
    fclose(logf);\
  } while (0)
#define LOGWRITE_ALWAYS(x...) do { \
    FILE * logf = fopen(LOGFILE, "a+"); \
    fprintf(logf, x);\
    fprintf(logf, "\n");\
    fclose(logf);\
  } while (0)
#define EXIT_WITH(x) do {\
    LOGWRITE_ALWAYS("Error %d in pid %d.", x, getpid());\
    LOGWRITE_ALWAYS("Error with info: %s", strerror(errno));\
    exit(1);\
  } while(0)

#ifdef DEBUG
// debugging is on, write detailed info into log file
#define LOGWRITE(x...) do { \
    FILE * logf = fopen(LOGFILE, "a+"); \
    fprintf(logf, x);\
    fprintf(logf, "\n");\
    fclose(logf);\
  } while (0)

#else
// disable debugging part to save resources
#define LOGWRITE(x...) (void)0

#endif



/*****************************
 * SysFuzz Predefine Part *
 *****************************/

// borrowed some code from afl-qemu-cpu-inl.h

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned int sysdig_sub_pid;

#define REC_BUFFER_SIZE 640+1

// the buffer for handling info stream from nodrop.ko
static unsigned char tmp3[REC_BUFFER_SIZE];

#define ADDITIONAL_MEM 100
#define MAXEVENT_NUM 1000

typedef sysfuzz_ulong __attribute__((aligned(32)));

// fds that will be used in our new mechanism
// communicate between 1 and 2
#define PIPE0_W_FD (FORKSRV_FD-2)
#define PIPE0_R_FD (FORKSRV_FD-3)
// // communicate between 2 and 3
// #define PIPE1_W_FD (FORKSRV_FD-4)
// #define PIPE1_R_FD (FORKSRV_FD-5)

// communicate with NoDrop monitor
#define EXIT_SIGW_FD 250
#define EXIT_SIGR_FD 251

/**************
 * Compare Mode Predefine *
 **************/
// use a bool buffer to store the traditional AFL tuples count number
bool comp_mode;
static bool oldtuples[MAP_SIZE + 10];
static bool newtuples[MAP_SIZE + 10];
#define SHOWMAP_OUT_PATH "./logs/cur_tuple"
#define COMP_RECORD_PATH "./logs/tupleComp.txt"
// AFL-instrumented target path
static char traditional_app_path[200];
// used to calculate all executions
unsigned long exec_count = 0;
// The exection count gap between two writes of old and new tuple numbers
#define COUNT_GAP 1000
// // limit the file number to save
#define MAX_EXEC_COUNT 10000000
// old executable path
u8* old_target_path;
// old bitmap
static u8* old_trace_bits;
// old shared memory id
int old_shm_id;
// the path to dump input files
#define CUR_INPUT_DUMP_PATH "/data/xjf/relationTest-gzip/afl-sys-inputs"

/**************
 * Lib Hooking Predefine *
 **************/
#define HOOKING_OUT_PATH "/data/xjf/hooking_out/hooking.out" 
#define HOOKING_LIB "./funchook/hooking.so"


/*************************
 * Syscall Informatino Collection *
 *************************/
// the n-grams length(aka, n)*2, note only even number supported 
#define GRAMS_N 128
#define MSG_BUFFER_SIZE 640+1+1+1
#define NGRAM_BUFFER_SIZE 6400+2
#define MAX_EVENTS 1000

// the stride
static int step = 1;
static int current_index = 0;
static int count = 0;
static int last_record_index = 0;
static int begin_to_record = 0;
// static char temp_grams[GRAMS_N][MSG_BUFFER_SIZE];
static char total_grams[MAX_EVENTS+GRAMS_N][MSG_BUFFER_SIZE];
// the total length of all these grams
static unsigned long long total_length = 0;

// helper functions for stream handling
static int _parse(char *out, struct nod_event_hdr *hdr, char *buffer, void *__data)
{
    size_t i;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;
    char temp_param[MSG_BUFFER_SIZE];

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return -1;

    info = &g_event_info[hdr->type];
    args = (uint16_t *)buffer;
    data = (char *)(args + info->nparams);
    
    // formatting
    // fprintf(out, "%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);
    sprintf(out, "%s\n", info->name);

    // // add param info
    // for (i = 0; i < info->nparams; ++i) {
    //     param = &info->params[i];
    //     // if (i > 0)  sprintf(out, ",");
    //     strcat(out, param->name);
    //     memset(temp_param, 0, sizeof(temp_param));
    //     switch(param->type) {
    //     case PT_CHARBUF:
    //     case PT_FSPATH:
    //     case PT_FSRELPATH:
    //     case PT_BYTEBUF:
    //         snprintf(temp_param, args[i], "%s", data);
    //         break;

    //     case PT_FLAGS8:
    //     case PT_UINT8:
    //     case PT_SIGTYPE:
    //         sprintf(temp_param, __print_format[PT_UINT8][param->fmt], *(uint8_t *)data);
    //         break;
    //     case PT_FLAGS16:
    //     case PT_UINT16:
    //     case PT_SYSCALLID:
    //         sprintf(temp_param, __print_format[PT_UINT16][param->fmt], *(uint16_t *)data);
    //         break;
        
    //     case PT_FLAGS32:
    //     case PT_UINT32:
    //     case PT_MODE:
    //     case PT_UID:
    //     case PT_GID:
    //     case PT_SIGSET:
    //         sprintf(temp_param, __print_format[PT_UINT32][param->fmt], *(uint32_t *)data);
    //         break;
        
    //     case PT_RELTIME:
    //     case PT_ABSTIME:
    //     case PT_UINT64:
    //         sprintf(temp_param, __print_format[PT_UINT64][param->fmt], *(uint64_t *)data);
    //         break;

    //     case PT_INT8:
    //         sprintf(temp_param, __print_format[PT_INT8][param->fmt], *(int8_t *)data);
    //         break;

    //     case PT_INT16:
    //         sprintf(temp_param, __print_format[PT_INT16][param->fmt], *(int16_t *)data);
    //         break;
        
    //     case PT_INT32:
    //         sprintf(temp_param, __print_format[PT_INT32][param->fmt], *(int32_t *)data);
    //         break;

    //     case PT_INT64:
    //     case PT_ERRNO:
    //     case PT_FD:
    //     case PT_PID:
    //         sprintf(temp_param, __print_format[PT_INT64][param->fmt], *(int64_t *)data);
    //         break;

    //     default:
    //         sprintf(temp_param, "?");
    //         break;
    //     }

    //     data += args[i];
    //     strcat(out, temp_param);
    // }
    // strcat(out, "\n");

    // LOGWRITE("%s", out);

    return 0;
}

void handleInfoStrmInit(){
  // change to NoDrop module
  // clean the buffer
  if (ioctl(device_fd, NOD_IOCTL_CLEAR_GLOBAL_BUFFER, 0))
    EXIT_WITH(100);

  // for(int i=0; i<GRAMS_N; ++i){
  //   memset(temp_grams[i], sizeof(temp_grams[i]), 0);
  // }

  for(int i=0; i<MAX_EVENTS+GRAMS_N; ++i){
    memset(total_grams[i], sizeof(total_grams[i]), 0);
  }
  current_index = 0;
  count = 0;
  last_record_index = 0;
  begin_to_record = 0;
  total_length = 0;
  LOGWRITE("handleInfoStrmInit over.");
}

// Info handing stream, the buffer size is only 2*stride, better when events are bigger
// void handleInfoStrm(char * evttype){
//   strcpy(temp_grams[current_index], evttype);
//   temp_grams[current_index][strlen(evttype)-1]="\0";
//   // LOGWRITE("Got message: %s", temp_grams[current_index]);
  
//   // turn on recording when N-gram reaches
//   if ((!begin_to_record) && (current_index >= GRAMS_N/2)){
//     begin_to_record = 1;
//     last_record_index = current_index;
//   }
//   // if we have started recording
//   if (begin_to_record){
//     int start_index = (current_index + GRAMS_N/2 ) % GRAMS_N;
//     if ( ( (current_index + GRAMS_N - last_record_index) % GRAMS_N) % step == 0) {
//       count += 1;
//       char ngramStr[NGRAM_BUFFER_SIZE];
//       int length = 0;
//       memset(ngramStr, 0, sizeof(ngramStr));
//       for(int i=start_index; i <= start_index + GRAMS_N/2-1; ++i){
//         int tempLen = strlen(temp_grams[i % GRAMS_N]);
//         if( (length + tempLen) > NGRAM_BUFFER_SIZE-3){
//           strncat(ngramStr, temp_grams[i % GRAMS_N], NGRAM_BUFFER_SIZE-2-length);
//           break;
//         }
//         else{
//           strncat(ngramStr, temp_grams[i % GRAMS_N], tempLen);
//           length += tempLen;
//         }
//       }
//       // transfer N-gram to hash number
//       u32 cur_loc = hash32(ngramStr, sizeof(ngramStr), HASH_CONST);
//       cur_loc &= MAP_SIZE-1;
//       if(cur_loc>MAP_SIZE) EXIT_WITH("111");

//       // LOGWRITE("%d-gram:%s 32-hash:%lld", GRAMS_N/2, ngramStr, cur_loc);

//       afl_area_ptr[cur_loc]++;
//       last_record_index = current_index;
//     }
//   }
//   current_index += 1;
//   if (current_index == GRAMS_N){
//     current_index = 0;
//   }
// }

// TODO: use a global buffer to store all the concated event names, 
// save the use of grams array...
void handleInfoStrm(char * evttype){
  strcpy(total_grams[current_index], evttype);
  total_grams[current_index][strlen(evttype)-1]="\0";
  LOGWRITE("Message:%s", evttype);
  
  // turn on recording when N-gram reaches
  if ((!begin_to_record) && (current_index >= GRAMS_N/2)){
    begin_to_record = 1;
    last_record_index = current_index;
  }
  // if we have started recording
  if (begin_to_record){
    int start_index = current_index - GRAMS_N/2;
    if(start_index > MAX_EVENTS) EXIT_WITH(100);
    if ( (current_index - last_record_index) % step == 0) {
      count += 1;
      char ngramStr[NGRAM_BUFFER_SIZE];
      int length = 0;
      memset(ngramStr, 0, sizeof(ngramStr));
      for(int i=start_index; i <= start_index + GRAMS_N/2-1; ++i){
        int tempLen = strlen(total_grams[i]);
        total_length += tempLen;
        if( (length + tempLen) > NGRAM_BUFFER_SIZE-3){
          strncat(ngramStr, total_grams[i], NGRAM_BUFFER_SIZE-2-length);
          break;
        }
        else{
          strncat(ngramStr, total_grams[i], tempLen);
          length += tempLen;
        }
      }
      // transfer N-gram to hash number
      u32 cur_loc = hash32(ngramStr, sizeof(ngramStr), HASH_CONST);
      cur_loc &= MAP_SIZE-1;
      if(cur_loc>MAP_SIZE) EXIT_WITH("111");

      // LOGWRITE("%d-gram:%s 32-hash:%lld", GRAMS_N/2, ngramStr, cur_loc);

      afl_area_ptr[cur_loc]++;
      last_record_index = current_index;
    }
  }
  current_index += 1;

}

void InfoStrm(){
  int ret;
  struct buffer_count_info cinfo;
  struct fetch_buffer_struct fetch;

  if ((ret = ioctl(device_fd, NOD_IOCTL_READ_GLOBAL_BUFFER_COUNT_INFO, &cinfo))) {
      LOGWRITE("Get Buffer Count Info failed, reason %d\n", ret);
      EXIT_WITH(101);
  }

  // Not enough to fill up a N-gram, skip
  // Todo: add something to make these short ones also considered...
  if (cinfo.unflushed_len < 1) {
      LOGWRITE("Too few events...");
      return;
  }

  fetch.len = cinfo.unflushed_len;
  fetch.buf = malloc(fetch.len);
  if (!fetch.buf) {
      LOGWRITE_ALWAYS( "Allocate memory failed\n");
      LOGWRITE_ALWAYS( "error: %s\n", strerror(errno));
      EXIT_WITH(102);
  }

  LOGWRITE("Event number: %d, Unflushed length: %d", 
      cinfo.unflushed_count, cinfo.unflushed_len);

  if ((ret = ioctl(device_fd, NOD_IOCTL_FETCH_GLOBAL_BUFFER, &fetch))) {
      LOGWRITE_ALWAYS("Fetch Global Buffer failed, reason %d\n", ret);
      EXIT_WITH(103);
  }

  // added from main.c to process raw data 
  struct nod_event_hdr *hdr;
  char *ptr, *buffer_end;
  ptr = fetch.buf;
  buffer_end = fetch.buf + fetch.len;
  while (ptr < buffer_end) {
      memset(tmp3, 0, sizeof(tmp3));

      hdr = (struct nod_event_hdr *)ptr; 
      _parse(tmp3, hdr, (char *)(hdr + 1), 0);
      ptr += hdr->len;
      // fill tmp3 with the new event name, and send to handleInfoStrm
      
      handleInfoStrm(tmp3);
  }

  // // add a hashing of the whole buffer
  // u32 total_hash = hash32(fetch.buf, fetch.len, HASH_CONST);
  // LOGWRITE("total hash is: %lld", total_hash);
  // total_hash &= MAP_SIZE;
  // afl_area_ptr[total_hash]++;

  // remember to free....
  free(fetch.buf);
  fetch.buf = NULL;

  // add a hashing of all grams
  char grams_in_one[total_length+10];
  memset(grams_in_one, 0, sizeof(grams_in_one));
  for(int i = 0; i < cinfo.unflushed_count; ++i){
    strncat(grams_in_one, total_grams[i], total_length);
  }
  u32 total_hash = hash32(grams_in_one, total_length, HASH_CONST);
  LOGWRITE("total hash is: %lld", total_hash);
  total_hash &= MAP_SIZE;
  afl_area_ptr[total_hash]++;

  

#ifdef LIB_HOOKING
  // add the info source from lib hooking...
  FILE* hooking_out = fopen(HOOKING_OUT_PATH, "r+");
  if(hooking_out == NULL)EXIT_WITH(302);
  ssize_t readlen;
  ssize_t len = 0; // getline() is able to resize buffer with realloc()

  // mark as the beginning of lib hooking info
  handleInfoStrm("LIBHOOK_BEGIN"); 
  while ((readlen = getline(&ptr, &len, hooking_out)) != -1){
    handleInfoStrm(ptr);
  }

  // remember to free...
  free(ptr);
  fclose(hooking_out);
#endif

  // all ends.
  LOGWRITE("InfoStrm ended.");
}



/*************************
 * Compare With Traditional AFL *
 *************************/

// borrowed from afl-showmap.c
/* Find old binary. */

static void find_old_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    old_target_path = ck_strdup(fname);

    if (stat(old_target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        old_target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        old_target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(old_target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4) break;

      ck_free(old_target_path);
      old_target_path = 0;

    }

    if (!old_target_path) FATAL("Program '%s' not found or not executable", fname);

  }

}

/* Get rid of shared memory (atexit handler). */

static void old_remove_shm(void) {

  shmctl(old_shm_id, IPC_RMID, NULL);

}

/* Configure old shared memory. */

static void setup_old_shm(void) {

  u8* shm_str;

  old_shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (old_shm_id < 0) PFATAL("shmget() failed");

  atexit(old_remove_shm);

  shm_str = alloc_printf("%d", old_shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  old_trace_bits = shmat(old_shm_id, NULL, 0);
  
  if (!old_trace_bits) PFATAL("shmat() failed");

}

// borrowed from afl-showmap.c
/* Execute target application and get traditional bitmap */

static void run_old_target(char** argv) {
  // modify the argv[0] to traditional app path
  argv[0] = old_target_path;
  LOGWRITE("run_old_target argv: %s, %s ...", argv[0], argv[1]);

  static struct itimerval it;
  int status = 0;
  // set timeout(ms)
  u32 old_exec_tmout = 50;

  LOGWRITE("-- Program output begins --");

  MEM_BARRIER();

  pid_t old_child_pid = fork();

  if (old_child_pid < 0) PFATAL("fork() failed");

  if (!old_child_pid) {

    struct rlimit r;

    // do not need mem limit because son process will inherit former limits...

    // allow core dumps.
    r.rlim_max = r.rlim_cur = RLIM_INFINITY;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    setsid();

    execv(old_target_path, argv);

    *(u32*)old_trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Configure timeout, wait for child, cancel timeout. */

  if (old_exec_tmout) {

    // child_timed_out = 0;
    it.it_value.tv_sec = (old_exec_tmout / 1000);
    it.it_value.tv_usec = (old_exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  if (waitpid(old_child_pid, &status, 0) <= 0) {
    LOGWRITE("waitpid() failed");
    EXIT_WITH(300);
  }

  old_child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32*)old_trace_bits == EXEC_FAIL_SIG)
    LOGWRITE("Unable to execute '%s'", argv[0]);

}



// copy and save the current input file to check our old tuples situation
// but not a good solution for the numberous fuzzed input files...
int copy_cur_input(unsigned long count, char * input_path){
  if(exec_count >= MAX_EXEC_COUNT){
    return;
  }
  char copy_command[100];
  memset(copy_command, 0, sizeof(copy_command));
  sprintf(copy_command, "cp %s %s/input_%09d", input_path, CUR_INPUT_DUMP_PATH, count);
  LOGWRITE("Copy command: %s", copy_command);
  return system(copy_command);
}

// write to ./logs/tuplesComp.txt
int write_tuplesComp(){
  // calculate all the tuples that have been hit
  int old_number = 0;
  int new_number = 0;
  // for (int i = 0; i < MAP_SIZE; ++i) {
  //   if(!oldtuples[i])continue;
  //   ++old_number;
  // }

  for (int j = 0; j < MAP_SIZE; ++j) {
    if (!newtuples[j])continue;
    ++new_number;
  }

  // then write the number into ./logs/tupleComp.txt
  FILE* comp_record = fopen(COMP_RECORD_PATH, "a");
  fprintf(comp_record, "%lu: %d\n", exec_count, new_number);
  fclose(comp_record);

}

// Calculate new bitmap, and 
// use afl-showmap to calculate the traditional bitmap
int TuplesCount(char * input_path, char** argv){
  LOGWRITE("oldTuplesCount");
  // MD5_hash_one(input_path);

  int ret = 0;
  int showmap_status = 0;

  /* Old method: 
     Use system() and afl-showmap executable, 
     but bitmap not changed across different input files...
     Not aware of the reason, maybe due to multiple process chaos*/
  // char showmap_cmd[200];

  // memset(showmap_cmd, 0, sizeof(showmap_cmd));
  // char *showmap_argv[] = {"afl-showmap", "-o", SHOWMAP_OUT_PATH, "-c", "-e", traditional_app_path, input_path};
  // sprintf(showmap_cmd, "afl-showmap -o %s -c -e %s %s", SHOWMAP_OUT_PATH, traditional_app_path, input_path);
  // ret = system(showmap_cmd);
  // LOGWRITE("afl-showmap command: %s", showmap_cmd);

  // // in the child process, execute afl-showmap
  // pid_t showmap_child = fork();
  // if(showmap_child < 0){
  //   EXIT_WITH(201);
  // }
  // else if(showmap_child == 0){
  //   execv("/usr/bin/afl-showmap", showmap_argv);
  // }
  // // wait for afl-showmap in the main process
  // ret = waitpid(showmap_child, &showmap_status, 0);
  // LOGWRITE("showmap returned with %d and status %d.", ret, showmap_status);

  // if(ret < 0){
  //   // something in the child process went wrong...
  //   EXIT_WITH(200);
  // }

  // // start to handle the tuple file
  // FILE* tuple_file = fopen(SHOWMAP_OUT_PATH, "r");
  // int tuple_number;
  // int hit_count;

  // // there is an empty line in tuple file, fscanf will be stuck in the last data line
  // // so we need to confirm EOF by new lines
  // int last_tuple_number = 0;
  
  // // now ret is used to calculate tuple numbers
  // ret = 0;
  // while (fscanf(tuple_file, "%6d:%d\n", &tuple_number, &hit_count)){
  //     if(tuple_number == last_tuple_number)break;
  //     oldtuples[tuple_number] = (hit_count!=0);
  //     // printf("%d:%d\n", tuple_number, hit_count);
  //     last_tuple_number = tuple_number;
  //     ++ret;
  // }
  
  // fclose(tuple_file);


  /* New method: 
    Move functions in afl-showmap here */
  // run_old_target(argv);
  

  // calculate new tuple edges 
  for (int i = 0; i < MAP_SIZE; ++i) {
    if ((afl_area_ptr[i])&(!newtuples[i]))newtuples[i] = true;
  }

// #ifdef DEBUG
  // record the input file
  copy_cur_input(exec_count, input_path);
// #endif

  return ret;
}


/*************************
 * AFL Forkserver Part *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(char *instrumented_path, bool need_comp) {
  // check if our method works.
  LOGWRITE_BEGIN("We have entered inside AFL_FORKSRV.");
  // if need comp, initialize the mode switch and comp recording file
  // save the use of need_comp, because afl-sys-showmap needs it
  comp_mode = need_comp;
  if(comp_mode){
    memset(oldtuples, 0, sizeof(oldtuples));
    memset(newtuples, 0, sizeof(newtuples));

    FILE * comp_record = fopen(COMP_RECORD_PATH, "w");
    fputs("Exection count: new tuple number\n", comp_record);
    fclose(comp_record);

    // we dont need it so far, maybe add parallel comparison in the future...
    memset(traditional_app_path, 0, sizeof(traditional_app_path));
    memcpy(traditional_app_path, instrumented_path, 100);
    LOGWRITE("traditional_app_path is: %s", traditional_app_path);

    // initialize afl-showmap stuff
    find_old_binary(instrumented_path);
    setup_old_shm();
  }
  

  char *id_str = getenv(SHM_ENV_VAR_NEW);

  int new_shm_id;

  if (id_str) {

    new_shm_id = atoi(id_str);
    afl_area_ptr = shmat(new_shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) EXIT_WITH(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    afl_area_ptr[0] = 1;
    LOGWRITE("AFL_AREA_PTR set ready.\n");
    return;
  }
  EXIT_WITH(1);
}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(char **argv, u8 *target_path, char * out_file) {
  LOGWRITE("out_file is: %s", out_file);

  // LOGWRITE("argv[0] and argv[1] is: %s, %s", argv[0], argv[1]);

  static unsigned char tmp[4];
  static unsigned char tmp1[4];
  // static pid_t tmp2;

  pid_t child_pid;
  // status: the status of the realrun process
  static int status2, status3;
  status3 = 0;

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, &status3, 4) != 4) return;

  afl_forksrv_pid = getpid();

  // used to communicate with nodrop.ko
  device_fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (device_fd < 0) {
      perror("Cannot open " NOD_IOCTL_PATH);
      EXIT_WITH(127);
  }

  /* All right, let's await orders... */

  while (1) {
    LOGWRITE("A work loop begins.");

    pid_t realrun_pid;
    // used to communicate with process No.3
    int pipe0_fd[2];
    if (pipe(pipe0_fd) || dup2(pipe0_fd[0], PIPE0_R_FD) < 0 || dup2(pipe0_fd[1], PIPE0_W_FD) < 0) EXIT_WITH(10);
    close(pipe0_fd[0]);
    close(pipe0_fd[1]);

    // - get command to run target
    if (read(FORKSRV_FD, tmp, 4) != 4) EXIT_WITH(2);

    // new implementation
    //create a new child, and this child is responsible for real execution.
    realrun_pid = fork();
    if(!realrun_pid){
      setsid();
      //in child, we do real execution once we received message from parent
      
      if (read(PIPE0_R_FD, tmp1, 4) != 4) EXIT_WITH(5);
      close(PIPE0_R_FD);
      
      /* Child process. Close descriptors and run free. */
      afl_fork_child = 1;

      // LOGWRITE("Hello from process No.3, my pid is %d", getpid());

#ifdef LIB_HOOKING
      // add lib hooking
      setenv("LD_PRELOAD", HOOKING_LIB, 1);
#endif
      // still use execv in our modification, 
      // maybe erase its overhead by returning to AFL's initial implementation idea...
      execv(target_path, argv);
      
      exit(1);
    }

    // LOGWRITE("Hello from process No.1, my pid is %d", getpid());

    handleInfoStrmInit();

    // send the child pid to fuzzer
    // ATTENTION!!!!! THIS IS THE PID THAT SIGALRM&CTRL-C WILL KILL
    if (write(FORKSRV_FD + 1, &realrun_pid, 4) != 4) EXIT_WITH(17);
    // LOGWRITE("Forkserver should be up.");

    // After init over, send message to process No.3
    if (write(PIPE0_W_FD , &realrun_pid, 4) != 4) EXIT_WITH(13);
    close(PIPE0_W_FD);

    if (waitpid(realrun_pid, &status3, 0) < 0) EXIT_WITH(19);
    LOGWRITE("Process No.3 ended with status:%d.", status3);

    // Note that we can only get the kernel buffer with syscall record after the process exited
    InfoStrm();

    // if need comp, do some relevant work here.
    if(comp_mode){
// #ifdef DEBUG
//       // check the input file...
//       system("python calculateMD5.py >> ./logs/logging.txt");
// #endif
      // feed in out_dir/.cur_input
      TuplesCount(out_file, argv);

      // write to file
      if(exec_count % COUNT_GAP == 0){
        write_tuplesComp();
      }
      ++exec_count;
    }
    
    // notify the main fuzzer that we have done
    if (write(FORKSRV_FD + 1, &status3, 4) != 4) EXIT_WITH(20);

    LOGWRITE("A work loop ended.\n");
  }


}




/* an exection-once map-detection function */

static void afl_sys_showmap(char **argv, u8 *target_path) {

  static unsigned char tmp[4];
  static unsigned char tmp1[4];
  // static pid_t tmp2;

  pid_t child_pid;
  // status: the status of the realrun process
  static int status2, status3;
  status3 = 0;

  if (!afl_area_ptr) return;

  // DO NOT NEED COMMUNICATION BECAUSE WE ONLY EXECUTE ONCE...
  // /* Tell the parent that we're alive. If the parent doesn't want
  //    to talk, assume that we're not running in forkserver mode. */

  // if (write(FORKSRV_FD + 1, &status3, 4) != 4) return;

  afl_forksrv_pid = getpid();

  // used to communicate with nodrop.ko
  device_fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (device_fd < 0) {
      perror("Cannot open " NOD_IOCTL_PATH);
      EXIT_WITH(127);
  }

  /* All right, let's await orders... */

  // while (1) {
  //   LOGWRITE("A work loop begins.");

    pid_t realrun_pid;
    // used to communicate with process No.3
    int pipe0_fd[2];
    if (pipe(pipe0_fd) || dup2(pipe0_fd[0], PIPE0_R_FD) < 0 || dup2(pipe0_fd[1], PIPE0_W_FD) < 0) EXIT_WITH(1);
    close(pipe0_fd[0]);
    close(pipe0_fd[1]);

    // // - get command to run target
    // if (read(FORKSRV_FD, tmp, 4) != 4) EXIT_WITH(2);

    // new implementation
    //create a new child, and this child is responsible for real execution.
    realrun_pid = fork();
    if(!realrun_pid){
      setsid();
      //in child, we do real execution once we received message from parent
        
      if (read(PIPE0_R_FD, tmp1, 4) != 4) EXIT_WITH(5);
      close(PIPE0_R_FD);
      
      /* Child process. Close descriptors and run free. */
      afl_fork_child = 1;

      LOGWRITE("Hello from process No.3, my pid is %d", getpid());

      // still use execv in our modification, 
      // maybe erase its overhead by returning to AFL's initial implementation idea...
      execv(target_path, argv);
      
      exit(1);
    }

    LOGWRITE("Hello from process No.1, my pid is %d", getpid());

    handleInfoStrmInit();

    // // send the child pid to fuzzer
    // // ATTENTION!!!!! THIS IS THE PID THAT SIGALRM&CTRL-C WILL KILL
    // if (write(FORKSRV_FD + 1, &realrun_pid, 4) != 4) EXIT_WITH(17);
    // LOGWRITE("Forkserver should be up.");

    // After init over, send message to process No.3
    if (write(PIPE0_W_FD , &realrun_pid, 4) != 4) EXIT_WITH(13);
    close(PIPE0_W_FD);

    if (waitpid(realrun_pid, &status3, 0) < 0) EXIT_WITH(19);
    LOGWRITE("Process No.3 ended with status:%d.", status3);

    // Note that we can only get the kernel buffer with syscall record after the process exited
    // Cancel the info processing when testing dumb mode 
    InfoStrm();
    
    // // notify the main fuzzer that we have done
    // if (write(FORKSRV_FD + 1, &status3, 4) != 4) EXIT_WITH(20);

    LOGWRITE("A work loop ended.\n");
  // }

    exit(0);

}
