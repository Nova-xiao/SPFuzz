#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
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
// #include <openssl/md5.h>
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

static unsigned char *afl_initialize;
static unsigned char *afl_area_ptr;

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned int sysdig_sub_pid;

#define REC_BUFFER_SIZE 640+1

// the buffer for handling info stream from nodrop.ko
static unsigned char tmp3[REC_BUFFER_SIZE];
// the buffer for handling info stream from wineserver
static char tmp4[REC_BUFFER_SIZE];
static char tmp5[REC_BUFFER_SIZE];

#define ADDITIONAL_MEM 100
#define MAXEVENT_NUM 1000

// typedef sysfuzz_ulong __attribute__((aligned(32)));

// fds that will be used in our new mechanism
// communicate between 1 and 2
#define PIPE0_W_FD (FORKSRV_FD-2)
#define PIPE0_R_FD (FORKSRV_FD-3)
// communicate with lsh.py
#define PIPE_LSH_W_FD (FORKSRV_FD-4)
#define PIPE_LSH_R_FD (FORKSRV_FD-5)


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
 * PERSISTENT Mode Predefine *
 **************/
int is_persistent= 0;

/**************
 * Lib Hooking Predefine *
 **************/
#define HOOKING_OUT_PATH "/data/xjf/hooking_out/hooking.out" 
#define HOOKING_LIB "./funchook/hooking.so"



/**************
 * Wine Part *
 **************/
#define WINESERVER_PATH "/opt/wine-stable/bin/wineserver"
#define WINESRV_LOG "./logs/winelog.txt"
// #define WINESRV_LOG "/tmp/my_fifo"
#define SPACE_ASCII 32
int pipe_wine_fd = -1;
FILE* wine_log = NULL;

// helper function for comparing string suffix
int EndsWith(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;

    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}


/*************************
 * LSH part *
 *************************/

// the pid and pgid of lsh.py process
pid_t lsh_pid;
pid_t lsh_pgid;
// the FILE struct of reading and writing with lsh.py 
FILE * lsh_read;
FILE * lsh_write;

// helper function to use LSHashing by lsh.py
static void setup_lsh(){
#ifdef LSH
  // Note! the process that calls this function should have valid STDIN_FD and STDOUT_FD...

  // set up pipes for lsh.py
  int pipe_r_lsh[2]; // for forkserver to read
  int pipe_w_lsh[2]; // for forkserver to write
  if(pipe(pipe_r_lsh) || dup2(pipe_r_lsh[0], PIPE_LSH_R_FD) < 0) EXIT_WITH(401);
  if(pipe(pipe_w_lsh) || dup2(pipe_w_lsh[1], PIPE_LSH_W_FD) < 0) EXIT_WITH(402);
  close(pipe_r_lsh[0]);
  close(pipe_w_lsh[1]);

  // setup lsh.py subprocess
  lsh_pid = fork();
  if(!lsh_pid){
    // lsh.py subprocess
    setsid();

    dup2(pipe_r_lsh[1], STDOUT_FILENO);
    dup2(pipe_w_lsh[0], STDIN_FILENO);
    close(pipe_r_lsh[1]);
    close(pipe_w_lsh[0]);

    // run lsh.py
    char *lsh_argv[] = {"/home/xjf/anaconda3/bin/python", "lsh.py", (char *)0 };
    execv(lsh_argv[0], lsh_argv);

    LOGWRITE("execv fail for: %s", strerror(errno));
    LOGWRITE("Why here?");
    exit(400);

  }

  lsh_pgid = getpgid(lsh_pid);
  LOGWRITE("pid and pgid of lsh.py are: %d , %d", lsh_pid, lsh_pgid);

  // forkserver
  close(pipe_r_lsh[1]);
  close(pipe_w_lsh[0]);

  // then send beginning param to lsh.py subprocess
  // (assume the number is not too big)
  unsigned char lsh_tmp[10];
  lsh_read = fdopen(PIPE_LSH_R_FD, "r");
  lsh_write = fdopen(PIPE_LSH_W_FD, "w");
  if(lsh_read == NULL || lsh_write == NULL) EXIT_WITH(404);
  LOGWRITE("Pipe file stream set up.");

  // if get "Got.", then connection is set up.
  if (fprintf(lsh_write, "%d\n", MAP_SIZE_POW2) < 0) EXIT_WITH(405);
  fflush(lsh_write);

  // LOGWRITE("Confirm message sent.");
  if (fscanf(lsh_read, "%s", lsh_tmp) == EOF ) EXIT_WITH(406);
  // LOGWRITE("Feedback message got.");
  if (strcmp("Got.", lsh_tmp)) EXIT_WITH(407);
  LOGWRITE("LSH pipe connection set up.");

#endif
}

// helper function to use LSHashing by lsh.py
static u32 use_lsh(char * str_tohash){

  u32 ret;
  fprintf(lsh_write, "%s\n", str_tohash);
  fflush(lsh_write);
  fscanf(lsh_read, "%d", &ret);

  return ret;
}

// helper function to terminate lsh.py
static void terminate_lsh(){
  
  if (lsh_pid > 0) {
    kill(lsh_pid, SIGKILL);
  }
  else{
    return;
  }

  LOGWRITE("lsh.py(pid=%d) should be killed now.", lsh_pid);

  // fclose(lsh_read);
  // fclose(lsh_write);

}


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
    sprintf(out, "%s ", info->name);

#ifdef LSH
    // Add param info.
    // Change all printing format to decimal, and reduce all PT_IGNORE param values to " "
    //  so that lsh.py can conveniently judge numberic or not.
    for (i = 0; i < info->nparams; ++i) {
        // if it is PT_IGNORE, dont add space at the end
        bool ignored = false;

        param = &info->params[i];
        // if (i > 0)  sprintf(out, ",");

        // strcat(out, param->name);
        // // add space for lsh.py to divide them
        // strcat(out, " ");

        memset(temp_param, 0, sizeof(temp_param));
        switch(param->type) {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            snprintf(temp_param, args[i], "%s", data);
            break;

        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            sprintf(temp_param, __print_format[PT_UINT8][PF_DEC], *(uint8_t *)data);
            break;
        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            sprintf(temp_param, __print_format[PT_UINT16][PF_DEC], *(uint16_t *)data);
            break;
        
        case PT_FLAGS32:
        case PT_UINT32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_SIGSET:
            sprintf(temp_param, __print_format[PT_UINT32][PF_DEC], *(uint32_t *)data);
            break;
        
        case PT_RELTIME:
        case PT_ABSTIME:
        case PT_UINT64:
            sprintf(temp_param, __print_format[PT_UINT64][PF_DEC], *(uint64_t *)data);
            break;

        case PT_INT8:
            sprintf(temp_param, __print_format[PT_INT8][PF_DEC], *(int8_t *)data);
            break;

        case PT_INT16:
            sprintf(temp_param, __print_format[PT_INT16][PF_DEC], *(int16_t *)data);
            break;
        
        case PT_INT32:
            sprintf(temp_param, __print_format[PT_INT32][PF_DEC], *(int32_t *)data);
            break;

        case PT_INT64:
        case PT_ERRNO:
        case PT_FD:
        case PT_PID:
            sprintf(temp_param, __print_format[PT_INT64][PF_DEC], *(int64_t *)data);
            break;

        default:
            sprintf(temp_param, "");
            ignored = true;
            break;
        }

        data += args[i];
        strcat(out, temp_param);

        // add space for lsh.py to divide them
        if(!ignored) strcat(out, " ");
    }
    // strcat(out, "\n");
#endif

    // add space for lsh.py to divide them
    // strcat(out, " ");

    // LOGWRITE(out);

    return 0;
}

void handleInfoStrmInit(){
  // change to NoDrop module
  // clean the buffer
  if (ioctl(device_fd, NOD_IOCTL_CLEAR_GLOBAL_BUFFER, 0))
    EXIT_WITH(104);

  // for(int i=0; i<GRAMS_N; ++i){
  //   memset(temp_grams[i], sizeof(temp_grams[i]), 0);
  // }

  for(int i=0; i<MAX_EVENTS+GRAMS_N; ++i){
    memset(total_grams[i], 0, sizeof(total_grams[i]));
  }
  current_index = 0;
  count = 0;
  last_record_index = 0;
  begin_to_record = 0;
  total_length = 0;

  LOGWRITE("handleInfoStrmInit over.");
}


void handleInfoStrm(char * evttype){
  strcpy(total_grams[current_index], evttype);
  // total_grams[current_index][strlen(evttype)-1]="\0";
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

      /* 
       *    In the traditional AFL design, we get an instrumented message of an edge(block-block),
       * and hash the edge number, store the hashing result in trace_bits(afl_area_ptr here).
       *    We will not replace the outside hashing algorithm, 
       * becasue we only want to replace the traditional edge with syscall traces,
       * and we use LSHashing because syscall traces can vary tremendously,  
       * but the trace_bits checksum calculation algorithm is free from this problem.
      */

#ifdef LSH
      u32 cur_loc = use_lsh(ngramStr);
#else
      u32 cur_loc = hash32(ngramStr, sizeof(ngramStr), HASH_CONST);
#endif
      
      cur_loc &= MAP_SIZE-1;
      if(cur_loc>MAP_SIZE) EXIT_WITH(111);


      // grams experiment
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

  // remember to free....
  free(fetch.buf);
  fetch.buf = NULL;

  // add a hashing of all grams
  char grams_in_one[total_length+10];
  memset(grams_in_one, 0, sizeof(grams_in_one));
  for(int i = 0; i < cinfo.unflushed_count; ++i){
    // LOGWRITE(total_grams[i]);
    strncat(grams_in_one, total_grams[i], total_length);
  }
  LOGWRITE("All grams (length: %d) in one is: ", total_length);
  LOGWRITE(grams_in_one);

#ifdef LSH
  // use LSHashing
  u64 all_grams_hash = use_lsh(grams_in_one);
  LOGWRITE("all grams hash(LSH) is: %lld", all_grams_hash);
#else
  u32 all_grams_hash = hash32(grams_in_one, total_length, HASH_CONST);
  LOGWRITE("all grams hash is: %lld", all_grams_hash);
#endif 
  
  all_grams_hash &= MAP_SIZE;
  // grams experiment
  afl_area_ptr[all_grams_hash]++;

  

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
 * For Wine-based Apps  *
 *************************/

void WineInfoStrmInit(){
  // kill the current wineserver (if there is one)
  system("wineserver -k");

  // we need to read syscall events from stderr of wineserver
  char command[50];
  memset(command, 0, sizeof(command));
  sprintf(command, "rm -rf %s", WINESRV_LOG);
  system(command);
  if (fopen(WINESRV_LOG, "w") == NULL) EXIT_WITH(777);
  // if (mkfifo(WINESRV_LOG, 0777) != 0) EXIT_WITH(777);
  
  // fork and execve wineserver
  pid_t wineserver_pid;
  wineserver_pid = fork();
  if(!wineserver_pid){
    // son process
    setsid();
    // redirect the stderr
    int winelog_fd = open(WINESRV_LOG, O_WRONLY);
    if (winelog_fd < 0) EXIT_WITH(779);
    if (dup2(winelog_fd, STDERR_FILENO) < 0) EXIT_WITH(780);

    // set wineserver params
    char *wineserver_argv[]={"wineserver","-d","-f",(char *)0};

    execv(WINESERVER_PATH, wineserver_argv);

    LOGWRITE("Why wineserver exited here?");
    exit(1);
  }

  LOGWRITE("Wineserver should be set up.");
  for(int i=0; i<MAX_EVENTS+GRAMS_N; ++i){
    memset(total_grams[i], 0, sizeof(total_grams[i]));
  }
  current_index = 0;
  last_record_index = 0;
  begin_to_record = 0;
  total_length = 0;

}

void WineInfoStrm(){
  // receive data
  wine_log = fopen(WINESRV_LOG , "r");
  if (wine_log == NULL) EXIT_WITH(778);

  // loop to read data
  count = 0;
  memset(tmp4, 0, sizeof(tmp4));
  while (fgets(tmp4, REC_BUFFER_SIZE, wine_log) != NULL) {
    if (count >= MAX_EVENTS ){
      // limit the max event num
      break;
    }
    if (count % 2 == 1){
      count++;
      // the syscalls are recorded twice
      continue;
    }
    
    // LOGWRITE("Raw data: %s", tmp4);
  
    // process the data
    memset(tmp5, 0, sizeof(tmp5));
    int tmp4_len = strlen(tmp4);
    int space_num = 0;
    int tmp5_idx = 0;
    bool star_starts = false;
    for(int tmp4_idx = 0; tmp4_idx < tmp4_len; ++tmp4_idx){
      if(tmp4[tmp4_idx] == ' '){
        space_num++;
        // if reached the ending space...
        if (space_num >= 2) break;
        // else, reached the first space
        else {
          continue;
        }
      }
      if (space_num == 1){
        // reached the starting space
        if (tmp4[tmp4_idx] == '*'){
          star_starts = true;
          break;
        }
        if (tmp4[tmp4_idx] == '(') continue;
        if (tmp4[tmp4_idx] == ')') continue;
        tmp5[tmp5_idx++] = tmp4[tmp4_idx];
      }
    }

    // if the content starts(and usually also ends with) '*', skip them
    if (star_starts) continue;

    LOGWRITE("Processed event (%d): %s", count/2, tmp5);
    handleInfoStrm(tmp5);

    memset(tmp4, 0, sizeof(tmp4));
    count++;
    current_index++;
  }

  // add a hashing of all grams
  char grams_in_one[total_length+10];
  memset(grams_in_one, 0, sizeof(grams_in_one));
  for(int i = 0; i < count; i+=2){
    // LOGWRITE(total_grams[i]);
    strncat(grams_in_one, total_grams[i], total_length);
  }

  LOGWRITE("All grams (length: %d) in one is: ", total_length);
  LOGWRITE(grams_in_one);

  // u32 all_grams_hash = hash32(grams_in_one, total_length, HASH_CONST);
  // LOGWRITE("all grams hash is: %lld", all_grams_hash);
  // all_grams_hash &= MAP_SIZE;
  // afl_area_ptr[all_grams_hash]++;

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
    return 0;
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

static void afl_setup(char *instrumented_path, bool need_comp, int persistent_mode) {

  // if persistent mode, the execution will be different
  is_persistent = persistent_mode;

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


  // original afl part
  char *id_str = getenv(SHM_ENV_VAR_NEW);

  int new_shm_id;

  if (id_str) {

    new_shm_id = atoi(id_str);
    afl_initialize = shmat(new_shm_id, NULL, 0);
    afl_area_ptr = afl_initialize;

    if (afl_area_ptr == (void*)-1) EXIT_WITH(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    afl_area_ptr[0] = 1;
    LOGWRITE("AFL_AREA_PTR set ready.\n");
    return;
  }

  // initialization failed
  EXIT_WITH(1);
}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(char **argv, u8 *target_path, char * out_file) {
  LOGWRITE("out_file is: %s", out_file);

  LOGWRITE("argv[0] and argv[1] is: %s, %s", argv[0], argv[1]);

  // static unsigned char tmp1[4];

  // FOR PERSISTENT MODE
  // NOTE: THESE TWO VARIABLES MUST BE OUTSIDE LOOP!!!
  unsigned int child_stopped = 0;
  pid_t child_pid;

  // status: the status of the realrun process
  static int status;
  status = 0;

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, &status, 4) != 4) return;

  afl_forksrv_pid = getpid();

  // used to communicate with nodrop.ko
  if (!EndsWith(argv[0], "wine")){
    LOGWRITE("Try to communicate with nodrop.ko...");
    device_fd = open(NOD_IOCTL_PATH, O_RDWR);
    if (device_fd < 0) {
        perror("Cannot open " NOD_IOCTL_PATH);
        EXIT_WITH(127);
    }
  }
  

  /* All right, let's await orders... */

  while (1) {
    LOGWRITE("A work loop begins.");
    // PERSISTENT MODE BUG: Can't use static char* here....
    unsigned int was_killed = 0;
    
    // used to communicate with process No.3
    int pipe0_fd[2];
    if (pipe(pipe0_fd) || dup2(pipe0_fd[0], PIPE0_R_FD) < 0 || dup2(pipe0_fd[1], PIPE0_W_FD) < 0) EXIT_WITH(10);
    close(pipe0_fd[0]);
    close(pipe0_fd[1]);

    // check if the target is running in wine mode
    // initialize 
    if(EndsWith(argv[0], "wine")){
      WineInfoStrmInit();
    }
    else handleInfoStrmInit();

    // - get command to run target
    if (read(FORKSRV_FD, &was_killed, 4) != 4) {
      fprintf(stderr, "Error: %s", strerror(errno));
      EXIT_WITH(2);
    }

    // FOR PERSISTENT 
    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */
    // LOGWRITE("child_stopped = %d", child_stopped);
    // LOGWRITE("was_killed = %d", was_killed);
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    // ADD PERSISTENT MODE
    if (!child_stopped){
      // LOGWRITE("Create a new child.");

      //create a new child, and this child is responsible for real execution.
      child_pid = fork();
      if(!child_pid){
        setsid();
        // Tryout: Can this sync be deleted?
        //in child, we do real execution once we received message from parent
        // if (read(PIPE0_R_FD, tmp1, 4) != 4) EXIT_WITH(5);
        close(PIPE0_R_FD);
        close(PIPE0_W_FD);
        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        
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
        
        LOGWRITE("Should not come to hades town...");
        exit(1);
      }

    }
    else{

      /* Special handling for persistent mode: if the child is alive but
        currently stopped, simply restart it with SIGCONT. */
      LOGWRITE("Send SIGCONT instead of restarting.");
      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }
    // LOGWRITE("Hello from process No.1, my pid is %d", getpid());


    // send the child pid to fuzzer
    // ATTENTION!!!!! THIS IS THE PID THAT SIGALRM&CTRL-C WILL KILL
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) EXIT_WITH(17);
    // LOGWRITE("Forkserver should be up.");

    // Tryout: delete this synchronization mechanism?
    // // After init over, send message to process No.3 to let it run
    // if (write(PIPE0_W_FD , &realrun_pid, 4) != 4) EXIT_WITH(13);
    // close(PIPE0_W_FD);

    // ADD PERSISTENT MODE
    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) EXIT_WITH(19);
    LOGWRITE("Child Process ended/stopped with status:%d.", status);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */
    if (WIFSTOPPED(status)) child_stopped = 1;
    else LOGWRITE("Child not stopped, but killed.\n");
    
    // Note that we can only get the kernel buffer with syscall record after the process exited
    // wine is the same...
    if (EndsWith(argv[0], "wine")){
      WineInfoStrm();
    }
    else InfoStrm();

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
    if (write(FORKSRV_FD + 1, &status, 4) != 4) EXIT_WITH(20);

    // close relevant fds and end this iteration.
    close(PIPE0_R_FD);
    close(PIPE0_W_FD);

    LOGWRITE("A work loop ended.\n");
  }


}


// A afl_persistent_loop function example...
// /* A simplified persistent mode handler, used as explained in README.llvm. */

// int __afl_persistent_loop(unsigned int max_cnt) {

//   static u8  first_pass = 1;
//   static u32 cycle_cnt;

//   if (first_pass) {

//     /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
//        On subsequent calls, the parent will take care of that, but on the first
//        iteration, it's our job to erase any trace of whatever happened
//        before the loop. */

//     if (is_persistent) {

//       memset(afl_area_ptr, 0, MAP_SIZE);
//       afl_area_ptr[0] = 1;
//     }

//     cycle_cnt  = max_cnt;
//     first_pass = 0;
//     return 1;

//   }

//   if (is_persistent) {

//     if (--cycle_cnt) {

//       raise(SIGSTOP);

//       afl_area_ptr[0] = 1;

//       return 1;

//     } else {

//       /* When exiting __AFL_LOOP(), make sure that the subsequent code that
//          follows the loop is not traced. We do that by pivoting back to the
//          dummy output region. */

//       afl_area_ptr = afl_initialize;

//     }

//   }

//   return 0;

// }


/* an exection-once map-detection function */

static void afl_sys_showmap(char **argv, u8 *target_path) {

  static unsigned char tmp[4];
  static unsigned char tmp1[4];
  // static pid_t tmp2;

  pid_t child_pid;
  // status: the status of the  process
  static int status2, status;
  status = 0;

  if (!afl_area_ptr) return;

  // DO NOT NEED COMMUNICATION BECAUSE WE ONLY EXECUTE ONCE...
  // /* Tell the parent that we're alive. If the parent doesn't want
  //    to talk, assume that we're not running in forkserver mode. */

  // if (write(FORKSRV_FD + 1, &status, 4) != 4) return;

  afl_forksrv_pid = getpid();

  // used to communicate with nodrop.ko
  device_fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (device_fd < 0) {
      perror("Cannot open " NOD_IOCTL_PATH);
      EXIT_WITH(128);
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

    if (waitpid(realrun_pid, &status, 0) < 0) EXIT_WITH(19);
    LOGWRITE("Process No.3 ended with status:%d.", status);

    // Note that we can only get the kernel buffer with syscall record after the process exited
    // Cancel the info processing when testing dumb mode 
    InfoStrm();
    
    // // notify the main fuzzer that we have done
    // if (write(FORKSRV_FD + 1, &status, 4) != 4) EXIT_WITH(20);

    LOGWRITE("A work loop ended.\n");
  // }

    exit(0);

}
