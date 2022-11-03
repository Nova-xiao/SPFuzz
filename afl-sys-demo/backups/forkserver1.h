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

extern int errno;
// borrowed some code from afl-qemu-cpu-inl.h

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned int sysdig_sub_pid;

/*****************************
 * SysFuzz Modification Part *
 *****************************/

// add a logging file under the qemu engine folder
#define LOGFILE "/root/xjf/afl-sys/logs/logging.txt"
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

#define MSG_BUFFER_SIZE 64+1+1+1

#define ADDITIONAL_MEM 200

typedef sysfuzz_ulong __attribute__((aligned(32)));

// fds that will be used in our new mechanism
#define PIPE0_W_FD (FORKSRV_FD-2)
#define PIPE0_R_FD (FORKSRV_FD-3)
#define PIPE1_W_FD (FORKSRV_FD-4)
#define PIPE1_R_FD (FORKSRV_FD-5)
#define PIPE2_W_FD (FORKSRV_FD-6)
#define PIPE2_R_FD (FORKSRV_FD-7)
#define PIPE3_W_FD (FORKSRV_FD-8)
#define PIPE3_R_FD (FORKSRV_FD-9) 

const char * fifoname = "/tmp/my_fifo";

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

static int stride = 1;
static int current_index = 0;
static int count = 0;
static int last_record_index = 0;
static int begin_to_record = 0;
static char temp_grams[16][64];

void testSysdig(){
  char command[64];
  memset(command, 0, sizeof(command));
  strcpy(command, "sysdig -n 2");
  int exitcode = system(command);
}

// a helper function for stream handling
void handleInfoStrm(char * evttype){
  strcpy(temp_grams[current_index], evttype);
  //remove the "\n" at the end
  temp_grams[current_index][strlen(temp_grams[current_index]) - 1] = (char)0;
  //printf("Got message: %s\n", temp_grams[current_index]);
  
  current_index += 1;
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
      char ngramStr[66];
      int length = 0;
      memset(ngramStr, 0, sizeof(ngramStr));
      for(int i=start_index; i <= start_index+7;++i){
        int tempLen = strlen(temp_grams[i%16]);
        if( (length + tempLen) > 64){
          strncat(ngramStr, temp_grams[i%16], 64-length);
          break;
        }
        else{
          strncat(ngramStr, temp_grams[i%16], tempLen);
          length += tempLen;
        }
      }
      printf("%64s\n", ngramStr);
      last_record_index = current_index;
    }
  }
  if (current_index == 16){
    current_index = 0;
  }
  
}

void sysdig_sig_handler(int signum){
    LOGWRITE("%d received signal %d", getpid(), signum);
    exit(1);
}

void sysdig_sig_handler1(int signum){
    LOGWRITE("%d received signal %d", getpid(), signum);
    system("ps -ef");
    printf("END\n");
    system("killall -9 sysdig");
    exit(1);
}

pid_t checkStatus(pid_t process_id){
    int status;
    pid_t return_pid = waitpid(process_id, &status, WNOHANG); /* WNOHANG def'd in wait.h */
    if (return_pid == -1) {
        /* error */
        LOGWRITE("%d returned with error status.", process_id);
    } else if (return_pid == 0) {
        /* child is still running */
        LOGWRITE("%d still running.", process_id);
    } else if (return_pid == process_id) {
        /* child is finished. exit status in status */
        LOGWRITE("%d returned normally.", process_id);
    }
    return return_pid;
}

/* Set up SHM region and initialize other stuff. */

static void afl_setup() {
  // check if our method works.
  LOGWRITE_BEGIN("We have entered inside AFL_FORKSRV.\n");

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
  static pid_t tmp2;
  static unsigned char tmp3[MSG_BUFFER_SIZE];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  /*
   Plan B?
   Maybe we can add a fork here to create sysdig as a son of the first-level parent,
   and this son need to process all info all the time, so we dont need to recreate it.
   */

  while (1) {
    LOGWRITE("A work loop begins.");

    pid_t child_pid;
    // status: the status of the realrun process
    static int status, temp_status;

    // used to communicate with process No.2
    int pipe0_fd[2];
    if (pipe(pipe0_fd) || dup2(pipe0_fd[0], PIPE0_R_FD) < 0 || dup2(pipe0_fd[1], PIPE0_W_FD) < 0) EXIT_WITH(1);
    close(pipe0_fd[0]);
    close(pipe0_fd[1]);

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) EXIT_WITH(2);

    child_pid = fork();
    if (child_pid < 0) EXIT_WITH(4);

    if (!child_pid) {
      /*
        This part is where our main modification to code lies.
        After our modification, 5 processes(3 of them are new) will be created:
        1. first-level parent: 
        |   do some communications with the main process, and enter the execution loop
        |   , just watch it from that on (if nothing goes wrong). 
        |___2. seconde-level parent(here, son of first-level parent)
            |   create sons and connect their pipes, do some sync work
            |___3. sysdig son (also son of second-level parent)
            |   |    wrapper for our sysdig script, dup its stdout to write pipe, 
            |   |   start sysdig and handle the info stream from it
            |   |___4. real process of sysdig 
            |
            |___5. real running process of the target program

        A normal work loop should work in an order like this:
        -- realrun process created and halt;
        -- sysdig wrapper create real running sysdig process;
        -- sysdig wrapper get init message from real running sysdig process, and send to forkserver;
        -- forkserver send message to realrun process;
        -- realrun process starts, and the sysdig wrapper get info from run running sysdig process;
        -- realrun process finished, forkserver kill real running sysdig process;
        -- real running sysdig process send message to its wrapper process at killed;
        -- sysdig wrapper process finish.

        Accordingly the logs should be like this:
       (-- Hello from 1;)
        -- Hello from 2;
        -- Hello from 3/4;
        -- Sysdig INIT over(sysdig wrapper);
        -- Received INIT message(forkserver);
        -- Hello from 5;
        -- Info loop...
        -- A work loop end.
       */
      
      // add our sysdig mechanism
      close(PIPE0_R_FD);
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      int pipe1_fd[2];
      pid_t realrun_pid;

      if (pipe(pipe1_fd) || dup2(pipe1_fd[0], PIPE1_R_FD) < 0 || dup2(pipe1_fd[1], PIPE1_W_FD) < 0) EXIT_WITH(4);
      close(pipe1_fd[0]);
      close(pipe1_fd[1]);

      LOGWRITE("Hello from process No.2, my pid is %d", getpid());

      //create a new child, and this child is responsible for real execution.
      realrun_pid = fork();
      
      if(!realrun_pid){
        setsid();
        //in child, we do real execution once we received message from parent
          
        if (read(PIPE1_R_FD, tmp1, 4) != 4) EXIT_WITH(5);
        
        /* Child process. Close descriptors and run free. */
        afl_fork_child = 1;

        LOGWRITE("Hello from process No.5, my pid is %d", getpid());

        // still use execv in our modification, 
        // maybe erase its overhead by returning to AFL's initial implementation idea...
        execv(target_path, argv);
        
        exit(1);
      }

      //in parent, we fork again to create a sysdig process, 
      //and handle the info stream from it
      close(PIPE1_R_FD);
      
      int pipe2_fd[2];
      //used to communicate between the sysdig process and the forkserver
      pid_t sysdig_pid;

      if (pipe(pipe2_fd) || dup2(pipe2_fd[1], PIPE2_W_FD) < 0 || dup2(pipe2_fd[0], PIPE2_R_FD) < 0) EXIT_WITH(6);
      close(pipe2_fd[1]);
      close(pipe2_fd[0]);

      sysdig_pid = fork();

      if(!sysdig_pid){
        signal(SIGINT, sysdig_sig_handler);

        int pipe3_fd[2];
        if (pipe(pipe3_fd) || dup2(pipe3_fd[1], PIPE3_W_FD) < 0 || dup2(pipe3_fd[0], PIPE3_R_FD) < 0) EXIT_WITH(7);
        //used to communicate between the sysdig process and the sysdig subprocess
        close(pipe3_fd[0]);
        close(pipe3_fd[1]);

        //fork a real running process of sysdig script
        sysdig_sub_pid = fork();

        if(!sysdig_sub_pid){
          signal(SIGINT, sysdig_sig_handler1);
          LOGWRITE("Hello from process No.4, my pid is %d", getpid());
          LOGWRITE("Process No.4 will monitor process No.5, whose pid is %d.", realrun_pid);
          // redirect STDOUT to pipe3 so that sysdig script can send message easily.
          if(dup2(PIPE3_W_FD, STDOUT_FILENO) < 0) EXIT_WITH(8);
        
          // execvp plan...
          // fill in the necessary params and execute it
          char sysdig_buf[64];
          if(sprintf(sysdig_buf, "%d", realrun_pid) < 0) exit(9);
          char *sysdig_argv[] = {"sysdig", "-n", "100000", "-c", "ngram-dev", sysdig_buf, NULL};
          LOGWRITE("Ready to execute sysdig with sysdig_buf: %s", sysdig_buf);

          execvp(sysdig_argv[0], sysdig_argv);
          // info process No.3 that we are ready
          // printf("INIT\n");
          // fflush(stdout);
          // char sysdig_buf[64];
          // memset(sysdig_buf, 0, sizeof(sysdig_buf));
          // if(sprintf(sysdig_buf, "sysdig -p \"%%evt.type\" proc.name=base64") < 0) exit(9);
          // int exitcode = system(sysdig_buf);
          // LOGWRITE("Sysdig exit with code %d", exitcode);
          
          exit(1);
        }

        // now is the sysdig wrapper process
        LOGWRITE("Hello from process No.3, my pid is %d", getpid());

        close(PIPE2_R_FD);
        close(PIPE3_W_FD);
        FILE * pipe3Stm = fdopen(PIPE3_R_FD, "r");
        // first, get the INIT message from sysdig script
        memset(tmp3, 0, sizeof(tmp3));
        LOGWRITE("%d Waiting for sysdig to initialize", getpid());
        if (fgets(tmp3, 65, pipe3Stm) == NULL) EXIT_WITH(10);
        LOGWRITE("Received message %sSysdig INIT over.", tmp3);
        // and notice process No.2 that sysdig is ready,
        // through the way of sending sysdig running process pid
        if ( write(PIPE2_W_FD, &sysdig_sub_pid, 4) !=4) EXIT_WITH(11); 

        memset(tmp3, 0, sizeof(tmp3));
        if (fgets(tmp3, 65, pipe3Stm) == NULL) EXIT_WITH(101);
        LOGWRITE("%d Received message: %s", getpid(), tmp3);
        if (!strcmp(tmp3, "END\n")){
          LOGWRITE("%d Received Ending message.", getpid());
          break;
        }
        FILE * tempfile = fopen("/root/xjf/afl-sys/logs/ngramLogs.txt", "r");
        
        //loop to repeatedly handle info stream
        while (1){
          // always looping until get SIGINT
          memset(tmp3, 0, sizeof(tmp3));
          if (fgets(tmp3, 65, tempfile) == NULL) {
            // checkStatus(sysdig_sub_pid);
            LOGWRITE("Get content: %s", tmp3);
            // EXIT_WITH(100);
            break;
          }
          // write info into bitmap(afl_area_ptr)

          // to fill up...

          // LOGWRITE("%d Received message: %s", getpid(), tmp3);
          // if (!strcmp(tmp3, "END\n")){
          //   LOGWRITE("%d Received Ending message.", getpid());
          //   break;
          // }
        }

        close(PIPE3_R_FD);
        exit(0);
      }

      //parent again
      close(PIPE2_W_FD);

      // get init over message from sysdig wrapper process
      // and this message is the sysdig subprocess pid (tmp2)
      if (read(PIPE2_R_FD, &tmp2, 4) != 4) EXIT_WITH(12);
      LOGWRITE("%d Received INIT message %d, notice process No.5 now.", getpid(), tmp2);

      //After sysdig init over, send message to process No.5
      if (write(PIPE1_W_FD , &realrun_pid, 4) != 4) EXIT_WITH(13);
      close(PIPE1_W_FD);

      // the real running process is over, we need to kill the two sysdig-related process
      if (waitpid(realrun_pid, &status, 0) < 0) EXIT_WITH(14);
      LOGWRITE("Process No.5 ended with status:%d.", status);
      checkStatus(tmp2);
      kill(tmp2, SIGINT);
      LOGWRITE("Kill message sent.");

      // and wait for sysdig wrapper process, 
      // all should finish after it finished.
      //kill(sysdig_pid, SIGINT);
      if (waitpid(sysdig_pid, &temp_status, 0) < 0) EXIT_WITH(15);
      LOGWRITE("process No.3 ends with status: %d", temp_status);
      
      // send the exit code of Process No.5 to Process No.1
      if (write(PIPE0_W_FD , &status, 4) != 4) EXIT_WITH(16);

      LOGWRITE("process No.2 ends now.");
      exit(0);
    }

    LOGWRITE("Hello from process No.1, my pid is %d", getpid());

    /* Parent. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) EXIT_WITH(17);

    /* Get exit status to main process. */

    if (read(PIPE0_R_FD, &status, 4) != 4) EXIT_WITH(18);

    if (waitpid(child_pid, &temp_status, 0) < 0) EXIT_WITH(19);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) EXIT_WITH(20);

    LOGWRITE("A work loop end with No.2 status: %d, No.5 status: %d.\n", temp_status, status);
  }

}
