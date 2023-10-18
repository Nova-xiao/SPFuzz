/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include "../../config.h"
#include "../../debug.h"

/*****************************
 * SysFuzz Modification Part *
 *****************************/

// add a logging file under the qemu engine folder
#define LOGFILE "/home/xjf/afl-sys/logs/logging.txt"
#define LOGWRITE(x...) do { \
    FILE * logf = fopen(LOGFILE, "a+"); \
    fprintf(logf, x);\
    fclose(logf);\
  } while (0)

// fds that will be used in our new mechanism
#define TSL_FD (FORKSRV_FD-1)
#define PIPE1_FD (FORKSRV_FD-2)
#define PIPE2_FD (FORKSRV_FD-3)



/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(itb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(cpu); \
    } \
    afl_maybe_log(itb->pc); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(abi_ulong);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {
  // check if our method works.
  LOGWRITE("We have entered inside QEMU.");

  static unsigned char tmp[4];
  static unsigned char tmp1[4];
  static unsigned char tmp2[4];

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

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {
      // old design. Overlook them.
      /*
       This part is where our main modification to code lies.
       After our modification, 4 processes will be created:
       1. first-level parent: 
          communicate with the main fuzzing process, push on the execution looping
       2. seconde-level parent(here, son of first-level parent)
          create two sons, and communicate with the sysdig son,
          process the info stream from sysdig son.
       3. real-run son (son of second-level parent)
          execute program once it gets message from 3.
       4. sysdig son (also son of second-level parent)
          wrapper for our sysdig script, dup its stdout to write pipe, 
          start sysdig and wait for it.
       */
      
      // add our sysdig mechanism
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);

      int pipe1_fd[2];
      pid_t realrun_pid;

      if (pipe(pipe1_fd) || dup2(pipe1_fd[0], PIPE1_FD) < 0) exit(4);
      close(pipe1_fd[0]);

      LOGWRITE("Hello from process No.2, my pid is %d\n", getpid());

      //create a new child, and this child is responsible for real execution.
      realrun_pid = fork();
      
      if(!realrun_pid){
        //in child, we do real execution once we received message from parent
          
        if (read(PIPE1_FD, tmp1, 4) != 4) exit(5);
        
        /* Child process. Close descriptors and run free. */

        afl_fork_child = 1;

        LOGWRITE("Hello from process No.3, my pid is %d\n", getpid());
        return;
      }

      //in parent, we fork again to create a sysdig process, 
      //and handle the info stream from it
      close(PIPE1_FD);
      
      int pipe2_fd[2];
      pid_t sysdig_pid;

      if (pipe(pipe2_fd) || dup2(pipe2_fd[1], PIPE2_FD) < 0) exit(6);
      close(pipe2_fd[1]);

      sysdig_pid = fork();

      if(!sysdig_pid){
        //in child that executes sysdig
        //to fill up ...
        LOGWRITE("Hello from process No.4, my pid is %d\n", getpid());
        char temp[8] = "INIT";
        if (write(PIPE2_FD , temp, 4) != 4) exit(7);
        //simulate info stream from sysdig
        strcpy(temp, "ENDMSGE");
        if ( (write(PIPE2_FD, temp, 7) != 7) || (strcmp(temp, "ENDMSGE")) ) exit(8);
        return;
      }

      //parent again
      close(PIPE2_FD);

      //get init over message from sysdig subprocess
      if (read(pipe2_fd[0], tmp2, 4) != 4) exit(9);
      LOGWRITE("%d Received INIT message.\n", getpid());

      //After sysdig init over, send message to the process that really runs target program
      if (write(pipe1_fd[1] , &realrun_pid, 4) != 4) exit(10);
      close(pipe1_fd[1]);

      if (waitpid(realrun_pid, &status, 0) < 0) exit(11);

      char temp[8];
      //loop to repeatedly handle info stream
      while (1){
          if (read(pipe2_fd[0], temp, 7) != 7) exit(11);
          LOGWRITE("%d Received message: %s.\n", getpid(), temp);
          if (!strcmp(temp, "ENDMSGE")){
              LOGWRITE("Received end message, parent ending.\n");
              break;
          }
      }
    
      return;

    }

    LOGWRITE("Hello from process No.1, my pid is %d\n", getpid());

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(12);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(13);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(14);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }

  close(fd);

}
