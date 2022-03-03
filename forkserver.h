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

extern int errno;
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, unsigned int);
int device_fd;

const char * md1 = "/home/xjf/afl-sys/kprobes/globals.ko";
const char * md2 = "/home/xjf/afl-sys/kprobes/modules.ko";
const char * logpath = "/home/xjf/afl-sys/logs/temp.txt";
// add a logging file
#define LOGFILE "/home/xjf/afl-sys/logs/logging.txt"

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

/*************************
 * Module modification PART *
 *************************/

// borrowed some code from insmod.c and rmmod.c
/* We use error numbers in a loose translation... */
static const char *moderror(int err)
{
	switch (err) {
	case ENOEXEC:
		return "Invalid module format";
	case ENOENT:
		return "Unknown symbol in module";
	case ESRCH:
		return "Module has wrong symbol version";
	case EINVAL:
		return "Invalid parameters";
	default:
		return strerror(err);
	}
}

static void *grab_file(const char *filename, unsigned long *size)
{
	unsigned int max = 16384;
	int ret, fd, err_save;
	void *buffer = malloc(max);
	if (!buffer)
		return NULL;

	fd = open(filename, O_RDONLY, 0);

	if (fd < 0)
		return NULL;

	*size = 0;
	while ((ret = read(fd, buffer + *size, max - *size)) > 0) {
		*size += ret;
		if (*size == max) {
			void *p;

			p = realloc(buffer, max *= 2);
			if (!p)
				goto out_error;
			buffer = p;
		}
	}
	if (ret < 0)
		goto out_error;

	close(fd);
	return buffer;

out_error:
	err_save = errno;
	free(buffer);
	close(fd);
	errno = err_save;
	return NULL;
}

/*
 * Get the basename in a pathname.
 * Unlike the standard implementation, this does not copy the string.
 * Helper function for filename2modname.
 */
char *my_basename(const char *path)
{
	const char *base = strrchr(path, '/');
	if (base)
		return (char *) base + 1;
	return (char *) path;
}

/*
 * Convert filename to the module name.  Works if filename == modname, too.
 */
void filename2modname(char *modname, const char *filename)
{
	const char *afterslash;
	unsigned int i;

	afterslash = my_basename(filename);

	/* Convert to underscores, stop at first . */
	for (i = 0; afterslash[i] && afterslash[i] != '.'; i++) {
		if (afterslash[i] == '-')
			modname[i] = '_';
		else
			modname[i] = afterslash[i];
	}
	modname[i] = '\0';
}

// insert module
void ModuleInsertion(const char * filename){
  long int ret;
	unsigned long len;
	void *file;
  file = grab_file(filename, &len);
	if (!file) {
		fprintf(stderr, "insmod: can't read '%s': %s\n",
			filename, strerror(errno));
		exit(1);
	}

	ret = init_module(file, len, "");
	if (ret != 0) {
		fprintf(stderr, "insmod: error inserting '%s': %li %s\n",
			filename, ret, moderror(errno));
		exit(1);
	}
}

// remove module
void ModuleRemovement(const char *path){
	long ret;
	char name[strlen(path) + 1];

	filename2modname(name, path);

  LOGWRITE("module to delete: %s", name);
	ret = delete_module(name, O_NONBLOCK|O_EXCL);
  LOGWRITE("delete_module returns: %ld", ret);
	if (ret != 0)
		fprintf(stderr, "Removing '%s'Error: %s\n", name, strerror(errno));
}

/*****************************
 * SysFuzz Modification Part *
 *****************************/

// borrowed some code from afl-qemu-cpu-inl.h

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned int sysdig_sub_pid;

#define MSG_BUFFER_SIZE 64+1+1+1

#define ADDITIONAL_MEM 0
#define MAXEVENT_NUM 200

typedef sysfuzz_ulong __attribute__((aligned(32)));

// fds that will be used in our new mechanism
// communicate between 1 and 2
#define PIPE0_W_FD (FORKSRV_FD-2)
#define PIPE0_R_FD (FORKSRV_FD-3)
// communicate between 2 and 3
#define PIPE1_W_FD (FORKSRV_FD-4)
#define PIPE1_R_FD (FORKSRV_FD-5)

#define PIPE2_W_FD (FORKSRV_FD-6)
#define PIPE2_R_FD (FORKSRV_FD-7)
#define PIPE3_W_FD (FORKSRV_FD-8)
#define PIPE3_R_FD (FORKSRV_FD-9) 

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

static int stride = 1;
static int current_index = 0;
static int count = 0;
static int last_record_index = 0;
static int begin_to_record = 0;
static char temp_grams[16][MSG_BUFFER_SIZE];

// helper functions for stream handling
void handleInfoStrmInit(){
  // // remove past temp files
  // if(access(logpath, F_OK)){
  //   remove(logpath);
  // }
  // // insert kprobe modules (note the insertion order)
  // // ModuleInsertion(md1);
  // ModuleInsertion(md2);

  // change to persistant version...
  ioctl(device_fd, 0);

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
        if( (length + tempLen) > 64){
          strncat(ngramStr, temp_grams[i%16], 64-length);
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
  static unsigned char tmp3[MSG_BUFFER_SIZE];
  // // remove kprobe modules and handle the info from it
  // // note the removement order
  // ModuleRemovement("modules");
  // // ModuleRemovement(md1);
  // LOGWRITE("Module remove over.");

  FILE * fp = fopen(logpath, "r");
  if(fp == NULL) EXIT_WITH(16);
  int i;
  for(i = 0; i < MAXEVENT_NUM; ++i){
    memset(tmp3, 0, sizeof(tmp3));
    if(fgets(tmp3, MSG_BUFFER_SIZE, fp)){
      handleInfoStrm(tmp3);
    }
    else{
      break;
    }
  }
  fclose(fp);
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

  // used to communicate with the module
  device_fd = open("/dev/test", O_RDWR); 
  if (device_fd < 0){
    perror("Failed to open the device...");
    EXIT_WITH(2);
  }

  /* All right, let's await orders... */

  while (1) {
    LOGWRITE("A work loop begins.");
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
      // add our mechanism
      close(PIPE0_R_FD);
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      // switch to root
      if(setuid(0)<0) EXIT_WITH(5);

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

        LOGWRITE("Hello from process No.3, my pid is %d", getpid());

        // still use execv in our modification, 
        // maybe erase its overhead by returning to AFL's initial implementation idea...
        execv(target_path, argv);
        
        exit(1);
      }

      // Parent
      close(PIPE1_R_FD);

      // Info Stream
      handleInfoStrmInit();
      
      //After init over, send message to process No.3
      if (write(PIPE1_W_FD , &realrun_pid, 4) != 4) EXIT_WITH(13);
      close(PIPE1_W_FD);

      // the real running process is over
      if (waitpid(realrun_pid, &status3, 0) < 0) EXIT_WITH(14);
      LOGWRITE("Process No.3 ended with status:%d.", status3);

      // Info Stream
      InfoStrm();
      
      // send the exit code of Process No.3 to Process No.1
      if (write(PIPE0_W_FD , &status3, 4) != 4) EXIT_WITH(17);

      LOGWRITE("process No.2 ends now.");
      exit(0);
    }

    /* Parent. */
    LOGWRITE("Hello from process No.1, my pid is %d", getpid());

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) EXIT_WITH(17);

    /* Get exit status to main process. */

    if (read(PIPE0_R_FD, &status3, 4) != 4) EXIT_WITH(18);

    if (waitpid(child_pid, &status2, 0) < 0) EXIT_WITH(19);
    if (write(FORKSRV_FD + 1, &status3, 4) != 4) EXIT_WITH(20);

    LOGWRITE("A work loop end with No.2 status: %d, No.3 status: %d.\n", status2, status3);
  }

}

