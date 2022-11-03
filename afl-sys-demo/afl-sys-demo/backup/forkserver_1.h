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

extern int errno;
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, unsigned int);
int device_fd;
uint64_t nevents;

#define NEVENTS_SIZE sizeof(nevents)

#ifdef CODE_PATH
#define MD1 CODE_PATH "/kprobes/globals.ko"
#define MD2 CODE_PATH "/kprobes/modules.ko"
#define LOGPATH CODE_PATH "/logs/temp.txt"
#define LOGFILE CODE_PATH "/logs/logging.txt"
#endif 

/*************************
 * Debugging Part *
 *************************/

#ifdef DEBUG
// debugging is on, write into log file
#define LOGWRITE_BEGIN(x...) do { \
    FILE * logf = fopen(LOGFILE, "w+"); \
    fprintf(logf, x);\
    fprintf(logf, "\n");\
    fclose(logf);\
  } while (0)
#define LOGWRITE(x...) do { \
    FILE * logf = fopen(LOGFILE, "a+"); \
    fprintf(logf, x);\
    fprintf(logf, "\n");\
    fclose(logf);\
  } while (0)
#define EXIT_WITH(x) do {\
    LOGWRITE("Error %d in pid %d.", x, getpid());\
    LOGWRITE("Error with info: %s", strerror(errno));\
    exit(1);\
  } while(0)

#else
// disable debugging part to save resources
#define LOGWRITE_BEGIN(x...) (void)0
#define LOGWRITE(x...) (void)0
#define EXIT_WITH(x) exit(1)

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

#define MSG_BUFFER_SIZE 256+1+1+1
#define REC_BUFFER_SIZE 32+1

// the buffer for handling info stream from nodrop.ko
static unsigned char tmp3[REC_BUFFER_SIZE];

#define ADDITIONAL_MEM 0
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

/*************************
 * Syscall Informatino Collection *
 *************************/

static int stride = 1;
static int current_index = 0;
static int count = 0;
static int last_record_index = 0;
static int begin_to_record = 0;
static char temp_grams[16][MSG_BUFFER_SIZE];

// helper functions for stream handling
void handleInfoStrmInit(){
  // change to NoDrop module
  // clean the buffer
  if (ioctl(device_fd, NOD_IOCTL_CLEAR_BUFFER, 0))
    EXIT_WITH(101);

  for(int i=0; i<16; ++i){
    memset(temp_grams[i], sizeof(temp_grams[i]), 0);
  }
  current_index = 0;
  count = 0;
  last_record_index = 0;
  begin_to_record = 0;
  LOGWRITE("handleInfoStrmInit over.");
}

void handleInfoStrm(char * evttype){
  strcpy(temp_grams[current_index], evttype);
  temp_grams[current_index][strlen(evttype)-1]="\0";
  // LOGWRITE("Got message: %s", temp_grams[current_index]);
  
  // turn on recording when 8-gram reaches
  if ((!begin_to_record) && (current_index >= 8)){
    begin_to_record = 1;
    last_record_index = current_index;
  }
  // if we have started recording
  if (begin_to_record){
    int start_index = (current_index+8)%16;
    if ( ( (current_index+16-last_record_index) % 16) % stride == 0) {
      count += 1;
      char ngramStr[MSG_BUFFER_SIZE];
      int length = 0;
      memset(ngramStr, 0, sizeof(ngramStr));
      for(int i=start_index; i <= start_index+7;++i){
        int tempLen = strlen(temp_grams[i%16]);
        if( (length + tempLen) > MSG_BUFFER_SIZE-3){
          strncat(ngramStr, temp_grams[i%16], MSG_BUFFER_SIZE-3-length);
          break;
        }
        else{
          strncat(ngramStr, temp_grams[i%16], tempLen);
          length += tempLen;
        }
      }
      u32 cur_loc = hash32(ngramStr, sizeof(ngramStr), HASH_CONST);
      cur_loc &= MAP_SIZE-1;
      if(cur_loc>MAP_SIZE) EXIT_WITH("111");
      LOGWRITE("8-gram:%s 32-hash:%lld", ngramStr, cur_loc);
      afl_area_ptr[cur_loc]++;
      last_record_index = current_index;
    }
  }
  current_index += 1;
  if (current_index == 16){
    current_index = 0;
  }
}

void InfoStrm(){
  size_t len = 0;
  ssize_t ret;
  FILE *nodrop_pipe = fdopen(EXIT_SIGR_FD, "r");
  // change to NoDrop module

  // loop to fetch data from nodrop.ko
  for(int i = 0; i < nevents; ++i){
    memset(tmp3, 0, sizeof(tmp3));
    if((ret = getline(&tmp3, &len, nodrop_pipe)) != -1){
      LOGWRITE("Got message: %s", tmp3);
      handleInfoStrm(tmp3);
    }
    else EXIT_WITH(120);
  }
  fclose(nodrop_pipe);
}

// pid_t checkStatus(pid_t process_id){
//     int status;
//     pid_t return_pid = waitpid(process_id, &status, WNOHANG); /* WNOHANG def'd in wait.h */
//     if (return_pid == -1) {
//         /* error */
//         LOGWRITE("%d returned with error status.", process_id);
//     } else if (return_pid == 0) {
//         /* child is still running */
//         LOGWRITE("%d still running.", process_id);
//     } else if (return_pid == process_id) {
//         /* child is finished. exit status in status */
//         LOGWRITE("%d returned normally.", process_id);
//     }
//     return return_pid;
// }

/*************************
 * AFL Forkserver Part *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup() {
  // check if our method works.
  LOGWRITE_BEGIN("We have entered inside AFL_FORKSRV.");

  char *id_str = getenv(SHM_ENV_VAR);

  int shm_id;

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

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

static void afl_forkserver(char **argv, u8 *target_path) {

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
    if (pipe(pipe0_fd) || dup2(pipe0_fd[0], PIPE0_R_FD) < 0 || dup2(pipe0_fd[1], PIPE0_W_FD) < 0) EXIT_WITH(1);
    close(pipe0_fd[0]);
    close(pipe0_fd[1]);

    // used to communicate with NoDrop monitor
    int pipe1_fd[2];
    if (pipe(pipe1_fd) || dup2(pipe1_fd[0], EXIT_SIGR_FD) < 0 || dup2(pipe1_fd[1], EXIT_SIGW_FD) < 0) EXIT_WITH(4);
    close(pipe1_fd[0]);
    close(pipe1_fd[1]);

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

      LOGWRITE("Hello from process No.3, my pid is %d", getpid());

      // still use execv in our modification, 
      // maybe erase its overhead by returning to AFL's initial implementation idea...
      execv(target_path, argv);
      
      exit(1);
    }

    LOGWRITE("Hello from process No.1, my pid is %d", getpid());
    handleInfoStrmInit();
    // send the child pid to fuzzer
    // ATTENTION!!!!! THIS IS THE PID THAT SIGALRM&CTRL-C WILL KILL
    if (write(FORKSRV_FD + 1, &realrun_pid, 4) != 4) EXIT_WITH(17);
    LOGWRITE("Forkserver should be up.");

    // After init over, send message to process No.3
    if (write(PIPE0_W_FD , &realrun_pid, 4) != 4) EXIT_WITH(13);
    close(PIPE0_W_FD);

    // get noticed from NoDrop monitor
    if (read(EXIT_SIGR_FD, &nevents, NEVENTS_SIZE) != NEVENTS_SIZE) EXIT_WITH(15);
    LOGWRITE("Get info from nodrop.ko: nevents is %d.", nevents);
    InfoStrm();
    LOGWRITE("Notify nodrop monitor to exit.");
    if (write(EXIT_SIGW_FD, &realrun_pid, 4) != 4) EXIT_WITH(16);
    close(EXIT_SIGW_FD);

    if (waitpid(realrun_pid, &status3, 0) < 0) EXIT_WITH(19);
    LOGWRITE("Process No.3 ended with status:%d.", status3);
    
    if (write(FORKSRV_FD + 1, &status3, 4) != 4) EXIT_WITH(20);
    LOGWRITE("A work loop ended.\n");
  }


}

