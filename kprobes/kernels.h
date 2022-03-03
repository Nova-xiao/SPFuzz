#ifndef _KERNELS_H_
#define _KERNELS_H_

#include <linux/kernel.h> 

struct mmap_info {
    char *data;
     unsigned int size;
     unsigned int in;
     unsigned int out;
};
extern struct mmap_info *info;
extern int Length;
#endif
