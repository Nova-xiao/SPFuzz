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

#include "export.h"
#include "types.h"
#include "alloc-inl.h"
#include "hash.h"
// #include <time.h>
// #include <sys/time.h>

extern int errno;



/*************************
 * NoDrop Ioctl Part *
 *************************/

int device_fd;



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

#define ADDITIONAL_MEM 100
#define MAXEVENT_NUM 1000

// typedef sysfuzz_ulong __attribute__((aligned(32)));

// fds that will be used in our new mechanism
// communicate between 1 and 2
#define PIPE0_W_FD (FORKSRV_FD-2)
#define PIPE0_R_FD (FORKSRV_FD-3)

// communicate with NoDrop monitor
#define EXIT_SIGW_FD 250
#define EXIT_SIGR_FD 251

/*************************
 * Syscall Information Collection *
 *************************/
// the n-grams length(aka, n)*2, note only even number supported 
#define GRAMS_N 256
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
    // size_t i;
    const struct nod_event_info *info;
    // const struct nod_param_info *param;
    // uint16_t *args;
    // char *data;
    // char temp_param[MSG_BUFFER_SIZE];

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return -1;

    info = &g_event_info[hdr->type];
    // args = (uint16_t *)buffer;
    // data = (char *)(args + info->nparams);
    
    // formatting
    // fprintf(out, "%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);
    sprintf(out, "%s ", info->name);

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


int handleInfoStrm(char * evttype){
  strcpy(total_grams[current_index], evttype);
  // total_grams[current_index][strlen(evttype)-1]="\0";
  LOGWRITE("Message:%s at %d", evttype, current_index);
  LOGTRACE("%s ", evttype);
  
  // turn on recording when N-gram reaches
  if ((!begin_to_record) && (current_index >= GRAMS_N/2)){
    begin_to_record = 1;
    last_record_index = current_index;
  }
  // if we have started recording
  if (begin_to_record){
    int start_index = current_index - GRAMS_N/2;
    if(start_index > MAX_EVENTS) {
      // seems to have bug...
      LOGWRITE_ALWAYS("start_index = %d ?", start_index);
      return 1;
    }
    if ( (current_index - last_record_index) % step == 0) {
      count += 1;
      char ngramStr[NGRAM_BUFFER_SIZE];
      int length = 0;
      memset(ngramStr, 0, sizeof(ngramStr));
      for(int i=start_index; i <= start_index + GRAMS_N/2-1; ++i){
        int tempLen = strlen(total_grams[i]);
        LOGWRITE("tempLen: %d", tempLen);
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
       * becasue we only want to replace the traditional edge with syscall traces
      */

      u32 cur_loc = hash64(ngramStr, sizeof(ngramStr), HASH_CONST);

      cur_loc &= MAP_SIZE-1;
      if(cur_loc>MAP_SIZE) EXIT_WITH(111);


      // grams experiment
      afl_area_ptr[cur_loc]++;
      last_record_index = current_index;
    }
  }
  current_index += 1;

  return 0;
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
      
      if(handleInfoStrm(tmp3)) break;
  }

  // remember to free....
  free(fetch.buf);
  fetch.buf = NULL;

  // add a hashing of all grams
  char grams_in_one[total_length+10];
  memset(grams_in_one, 0, sizeof(grams_in_one));
  // BUG: dont know why the count can be bigger than MAX_EVENTS...
  int total_count = (cinfo.unflushed_count > 1000) ? 1000 : cinfo.unflushed_count;

  for(int i = 0; i < total_count; ++i){
    LOGWRITE(total_grams[i]);
    strncat(grams_in_one, total_grams[i], total_length);
  }
  LOGWRITE("All grams (length: %d) in one is: ", total_length);
  LOGWRITE(grams_in_one);
  LOGTRACE("\n");

  u32 all_grams_hash = hash64(grams_in_one, total_length, HASH_CONST);
  LOGWRITE("all grams hash is: %lld", all_grams_hash);
  
  all_grams_hash &= MAP_SIZE;
  // grams experiment
  afl_area_ptr[all_grams_hash]++;


  // all ends.
  LOGWRITE("InfoStrm ended.");
}


/*************************
 * AFL Forkserver Part *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_sys_setup() {
  LOGWRITE_BEGIN("Set up shared memory.");
  // original afl part
  char *id_str = getenv(SHM_ENV_VAR);

  int new_shm_id;

  if (id_str) {

    new_shm_id = atoi(id_str);
    afl_initialize = shmat(new_shm_id, NULL, 0);
    afl_area_ptr = afl_initialize;

    if (afl_area_ptr == (void*)-1) EXIT_WITH(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    afl_area_ptr[0] = 1;
    LOGWRITE("AFL_AREA_PTR set with shm_id: %d.\n", new_shm_id);
    return;
  }

  // initialization failed
  EXIT_WITH(1);
}


/* Fork server logic, invoked once we hit _start. */

static void afl_sys_forkserver(u8 *target_path, char **argv) {
  LOGWRITE_ALWAYS("Forkserver starts with pid %d.", getpid());

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
  LOGWRITE("Try to communicate with nodrop.ko...");
  device_fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (device_fd < 0) {
      perror("Cannot open " NOD_IOCTL_PATH);
      EXIT_WITH(127);
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
    
    handleInfoStrmInit();

    // - get command to run target
    if (read(FORKSRV_FD, &was_killed, 4) != 4) {
      fprintf(stderr, "Error: %s", strerror(errno));
      EXIT_WITH(2);
    }

    // FOR PERSISTENT (NOT FULLY IMPLEMENTED YET)
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

        // still use execv in our modification, 
        // maybe erase its overhead by returning to AFL's initial implementation idea...
        execv(target_path, argv);
        
        LOGWRITE("You...should not come to hades town...");
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

    if (waitpid(child_pid, &status, 0) < 0) EXIT_WITH(19);
    LOGWRITE("Child Process ended/stopped with status:%d.", status);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */
    if (WIFSTOPPED(status)) child_stopped = 1;
    else LOGWRITE("Child not stopped, but killed.\n");
    
    // Note that we can only get the kernel buffer with syscall record after the process exited
    InfoStrm();

    // notify the main fuzzer that we have done
    if (write(FORKSRV_FD + 1, &status, 4) != 4) EXIT_WITH(20);

    // close relevant fds and end this iteration.
    close(PIPE0_R_FD);
    close(PIPE0_W_FD);

    LOGWRITE("A work loop ended.\n");
  }


}

