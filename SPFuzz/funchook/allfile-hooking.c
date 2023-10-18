/*** Nova Xiao: 
 * based on ycx's code, but add some macros to control the 
 * complexity of our record (remove the params)
 ***/
#define SIMPLE 1
/* base of the function hooking source code. */
#include <signal.h>
#include <stdarg.h>
#include <dirent.h>

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define BUFF_SIZE 500 // 500 for a function
#define HOOKING_OUT_PATH "/data/xjf/hooking_out/hooking.out" // saved output file path

int sfd = -1;
char sep = '\n'; // define '\n' as the separator.

size_t len(const char* str) {
  const char *char_ptr;
  const unsigned long int *longword_ptr;
  unsigned long int longword, himagic, lomagic;
  /* Handle the first few characters by reading one character at a time.
     Do this until CHAR_PTR is aligned on a longword boundary.  */
  for (char_ptr = str; ((unsigned long int) char_ptr
                        & (sizeof (longword) - 1)) != 0;
       ++char_ptr)
    if (*char_ptr == '\0')
      return char_ptr - str;
  /* All these elucidatory comments refer to 4-byte longwords,
     but the theory applies equally well to 8-byte longwords.  */
  longword_ptr = (unsigned long int *) char_ptr;
  /* Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
     the "holes."  Note that there is a hole just to the left of
     each byte, with an extra at the end:
     bits:  01111110 11111110 11111110 11111111
     bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
     The 1-bits make sure that carries propagate to the next 0-bit.
     The 0-bits provide holes for carries to fall into.  */
  himagic = 0x80808080L;
  lomagic = 0x01010101L;
  if (sizeof (longword) > 4)
    {
      /* 64-bit version of the magic.  */
      /* Do the shift in two steps to avoid a warning if long has 32 bits.  */
      himagic = ((himagic << 16) << 16) | himagic;
      lomagic = ((lomagic << 16) << 16) | lomagic;
    }
  if (sizeof (longword) > 8)
    abort ();
  /* Instead of the traditional loop which tests each character,
     we will test a longword at a time.  The tricky part is testing
     if *any of the four* bytes in the longword in question are zero.  */
  for (;;)
    {
      longword = *longword_ptr++;
      if (((longword - lomagic) & ~longword & himagic) != 0)
        {
          /* Which of the bytes was the zero?  If none of them were, it was
             a misfire; continue the search.  */
          const char *cp = (const char *) (longword_ptr - 1);
          if (cp[0] == 0)
            return cp - str;
          if (cp[1] == 0)
            return cp - str + 1;
          if (cp[2] == 0)
            return cp - str + 2;
          if (cp[3] == 0)
            return cp - str + 3;
          if (sizeof (longword) > 4)
            {
              if (cp[4] == 0)
                return cp - str + 4;
              if (cp[5] == 0)
                return cp - str + 5;
              if (cp[6] == 0)
                return cp - str + 6;
              if (cp[7] == 0)
                return cp - str + 7;
            }
        }
    }
}

int get_sfd(){
    if(sfd != -1) {
        return sfd;
    } else {
        // add O_TRUNC to remove former file
        int flags = O_CREAT | O_RDWR | O_TRUNC;
        mode_t modes = S_IRWXU | S_IRWXG;
        int (*old_open)(const char *path, int flags, mode_t mode);
        old_open = dlsym(RTLD_NEXT, "open");
        sfd = old_open(HOOKING_OUT_PATH, flags, modes);
        return sfd;
    }
}

int hook_log(int fd, const char* msg){
    ssize_t (*old_write)(int fd, const void *buf, size_t count);
    ssize_t result;
    old_write = dlsym(RTLD_NEXT, "write");
    result = old_write(fd, msg, len(msg));
}

// macros to reduce code amount
#ifndef SIMPLE

#define BEFORE_LOG(name, x...) do { \
    char hook_buff[BUFF_SIZE]; \
    sprintf(hook_buff, name); \
    sprintf(hook_buff + len(hook_buff), x); \
    int sfd = get_sfd(); \
    hook_log(sfd, hook_buff); \
} while (0)

#else

#define BEFORE_LOG(name, x...) do { \
    char hook_buff[BUFF_SIZE]; \
    sprintf(hook_buff, name); \
    int sfd = get_sfd(); \
    hook_log(sfd, hook_buff); \
} while (0)

#endif

#ifndef SIMPLE

#define AFTER_LOG(x...) do { \
    char hook_buff_after[BUFF_SIZE]; \
    sprintf(hook_buff_after, x); \
    sprintf(hook_buff_after + len(hook_buff_after), "%c", sep); \
    int sfd = get_sfd(); \
    hook_log(sfd, hook_buff_after); \
} while (0)

#else

#define AFTER_LOG(x...) do { \
    char hook_buff_after[BUFF_SIZE]; \
    sprintf(hook_buff_after, "%c", sep); \
    int sfd = get_sfd(); \
    hook_log(sfd, hook_buff_after); \
} while (0)

#endif



int atoi(const char * nptr)
{
    BEFORE_LOG("atoi", "((%s))", nptr);

    
    int (*old_atoi)(const char * nptr);
    int result;
    old_atoi = dlsym(RTLD_NEXT, "atoi");
    result = old_atoi(nptr);

    
    AFTER_LOG("==%d", result);

    return result;

}




int chmod(const char * file, __mode_t mode)
{
    BEFORE_LOG("chmod", "");

    
    int (*old_chmod)(const char * file, __mode_t mode);
    int result;
    old_chmod = dlsym(RTLD_NEXT, "chmod");
    result = old_chmod(file, mode);

    
    AFTER_LOG("==%d", result);


    return result;

}




int chown(const char * file, __uid_t owner, __gid_t group)
{
    
    BEFORE_LOG("chown", "");

    
    int (*old_chown)(const char * file, __uid_t owner, __gid_t group);
    int result;
    old_chown = dlsym(RTLD_NEXT, "chown");
    result = old_chown(file, owner, group);

    
    AFTER_LOG("==%d", result);

    return result;

}




int close(int fd)
{
    
    BEFORE_LOG("close", "");

    
    int (*old_close)(int fd);
    int result;
    old_close = dlsym(RTLD_NEXT, "close");
    result = old_close(fd);

    
    AFTER_LOG("==%d", result);

    return result;

}




int closedir(DIR * dirp)
{
    
    BEFORE_LOG("closedir", "");

    
    int (*old_closedir)(DIR * dirp);
    int result;
    old_closedir = dlsym(RTLD_NEXT, "closedir");
    result = old_closedir(dirp);

    
    AFTER_LOG("==%d", result);

    return result;

}




void exit(int status)
{
    
    BEFORE_LOG("exit", "");

    
    void (*old_exit)(int status);
    old_exit = dlsym(RTLD_NEXT, "exit");
    old_exit(status);

    
    AFTER_LOG("");

}




int fflush(FILE * stream)
{
    
    BEFORE_LOG("fflush", "");

    
    int (*old_fflush)(FILE * stream);
    int result;
    old_fflush = dlsym(RTLD_NEXT, "fflush");
    result = old_fflush(stream);

    
    AFTER_LOG("==%d", result);

    return result;

}




int fileno(FILE * stream)
{
    
    BEFORE_LOG("fileno", "");

    
    int (*old_fileno)(FILE * stream);
    int result;
    old_fileno = dlsym(RTLD_NEXT, "fileno");
    result = old_fileno(stream);

    
    AFTER_LOG("==%d", result);

    return result;

}



int fprintf(FILE* stream, const char* format, ...){
    
    BEFORE_LOG("fprintf", "");


    // refer to https://code.woboq.org/userspace/glibc/stdio-common/fprintf.c.html
    va_list arg;
    int done;
    va_start(arg, format);
    done = vfprintf(stream, format, arg);
    va_end (arg);


    AFTER_LOG("==%d", done);

    return done;
}



int fputc(int c, FILE * stream)
{
    
    BEFORE_LOG("fputc", "");

    
    int (*old_fputc)(int c, FILE * stream);
    int result;
    old_fputc = dlsym(RTLD_NEXT, "fputc");
    result = old_fputc(c, stream);

    
    AFTER_LOG("==%d", result);

    return result;

}




size_t fwrite(const void * restrict ptr, size_t size, size_t n, FILE * restrict s)
{
    
    BEFORE_LOG("fwrite", "");

    
    size_t (*old_fwrite)(const void * restrict ptr, size_t size, size_t n, FILE * restrict s);
    size_t result;
    old_fwrite = dlsym(RTLD_NEXT, "fwrite");
    result = old_fwrite(ptr, size, n, s);

    
    AFTER_LOG("==%lu", result);

    return result;

}




char * getenv(const char * name)
{
    
   BEFORE_LOG("getenv", "");

    
    char * (*old_getenv)(const char * name);
    char * result;
    old_getenv = dlsym(RTLD_NEXT, "getenv");
    result = old_getenv(name);


    AFTER_LOG("");

    return result;

}




int isatty(int fd)
{
    
    BEFORE_LOG("isatty", "");

    
    int (*old_isatty)(int fd);
    int result;
    old_isatty = dlsym(RTLD_NEXT, "isatty");
    result = old_isatty(fd);

    
    AFTER_LOG("==%d", result);

    return result;

}




int memcmp(const void * s1, const void * s2, size_t n)
{
    
    BEFORE_LOG("memcmp", "");

    
    int (*old_memcmp)(const void * s1, const void * s2, size_t n);
    int result;
    old_memcmp = dlsym(RTLD_NEXT, "memcmp");
    result = old_memcmp(s1, s2, n);

    
    AFTER_LOG("==%d", result);

    return result;

}




void * memset(void * s, int c, size_t n)
{
    
    BEFORE_LOG("memset", "");

    
    void * (*old_memset)(void * s, int c, size_t n);
    void * result;
    old_memset = dlsym(RTLD_NEXT, "memset");
    result = old_memset(s, c, n);

    
    AFTER_LOG("");

    return result;

}




int open(const char *pathname, int flags, ...) {

    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
        // sprintf(hook_buff, "open((%s;%d;%u))", pathname, flags, mode);
    } 

    BEFORE_LOG("open", "");
    
    
    int (*unhooked_open)(const char *pathname, int flags, mode_t mode);
    int result;
    unhooked_open = dlsym(RTLD_NEXT, "open");
    result = unhooked_open(pathname, flags, mode);


    AFTER_LOG("==%d", result);

    return result;
}



DIR * opendir(const char * name)
{
    
    BEFORE_LOG("opebdir", "");

    
    DIR * (*old_opendir)(const char * name);
    DIR * result;
    old_opendir = dlsym(RTLD_NEXT, "opendir");
    result = old_opendir(name);

    
    AFTER_LOG("");

    return result;

}




void perror(const char * s)
{
    
    BEFORE_LOG("perror", "");

    
    void (*old_perror)(const char * s);
    old_perror = dlsym(RTLD_NEXT, "perror");
    old_perror(s);

    
    AFTER_LOG("");

}




int putc(int c, FILE * stream)
{
    
    BEFORE_LOG("putc", "");

    
    int (*old_putc)(int c, FILE * stream);
    int result;
    old_putc = dlsym(RTLD_NEXT, "putc");
    result = old_putc(c, stream);

    
    AFTER_LOG("==%d", result);

    return result;

}




ssize_t read(int fd, void * buf, size_t nbytes)
{
    
    BEFORE_LOG("read", "");

    
    ssize_t (*old_read)(int fd, void * buf, size_t nbytes);
    ssize_t result;
    old_read = dlsym(RTLD_NEXT, "read");
    result = old_read(fd, buf, nbytes);

    
    AFTER_LOG("");

    return result;

}




struct dirent * readdir(DIR * dirp)
{
    
    BEFORE_LOG("readdir", "");

    
    struct dirent * (*old_readdir)(DIR * dirp);
    struct dirent * result;
    old_readdir = dlsym(RTLD_NEXT, "readdir");
    result = old_readdir(dirp);

    
    AFTER_LOG("");

    return result;

}




__sighandler_t signal(int sig, __sighandler_t handler)
{
    
    BEFORE_LOG("signal", "");

    
    __sighandler_t (*old_signal)(int sig, __sighandler_t handler);
    __sighandler_t result;
    old_signal = dlsym(RTLD_NEXT, "signal");
    result = old_signal(sig, handler);

    
    AFTER_LOG("");

    return result;

}




char * strcat(char * restrict dest, const char * restrict src)
{
    
    BEFORE_LOG("strcat", "");

    
    char * (*old_strcat)(char * restrict dest, const char * restrict src);
    char * result;
    old_strcat = dlsym(RTLD_NEXT, "strcat");
    result = old_strcat(dest, src);

    
    AFTER_LOG("");

    return result;

}




char * strchr(char * s, int c)
{
    
    BEFORE_LOG("strchr", "");

    
    char * (*old_strchr)(char * s, int c);
    char * result;
    old_strchr = dlsym(RTLD_NEXT, "strchr");
    result = old_strchr(s, c);

    
    AFTER_LOG("");

    return result;

}




int strcmp(const char * s1, const char * s2)
{
    
    BEFORE_LOG("strcmp", "");

    
    int (*old_strcmp)(const char * s1, const char * s2);
    int result;
    old_strcmp = dlsym(RTLD_NEXT, "strcmp");
    result = old_strcmp(s1, s2);

    
    AFTER_LOG("==%d", result);

    return result;

}




char * strcpy(char * restrict dest, const char * restrict src)
{
    
    BEFORE_LOG("strcpy", "");

    
    char * (*old_strcpy)(char * restrict dest, const char * restrict src);
    char * result;
    old_strcpy = dlsym(RTLD_NEXT, "strcpy");
    result = old_strcpy(dest, src);

    
    AFTER_LOG("");

    return result;

}




size_t strcspn(const char * s, const char * reject)
{
    
    BEFORE_LOG("strcspn", "");

    
    size_t (*old_strcspn)(const char * s, const char * reject);
    size_t result;
    old_strcspn = dlsym(RTLD_NEXT, "strcspn");
    result = old_strcspn(s, reject);

    
    AFTER_LOG("==%lu", result);

    return result;

}




size_t strlen(const char * s)
{
    
    BEFORE_LOG("strlen", "");

    
    size_t (*old_strlen)(const char * s);
    size_t result;
    old_strlen = dlsym(RTLD_NEXT, "strlen");
    result = old_strlen(s);

    
    AFTER_LOG("==%lu", result);

    return result;

}




int strncmp(const char * s1, const char * s2, size_t n)
{
    
    BEFORE_LOG("strncmp", "");

    
    int (*old_strncmp)(const char * s1, const char * s2, size_t n);
    int result;
    old_strncmp = dlsym(RTLD_NEXT, "strncmp");
    result = old_strncmp(s1, s2, n);

    
    AFTER_LOG("==%d", result);

    return result;

}




char * strncpy(char * restrict dest, const char * restrict src, size_t n)
{
    
    BEFORE_LOG("strncpy", "");

    
    char * (*old_strncpy)(char * restrict dest, const char * restrict src, size_t n);
    char * result;
    old_strncpy = dlsym(RTLD_NEXT, "strncpy");
    result = old_strncpy(dest, src, n);

    
    AFTER_LOG("");

    return result;

}




char * strrchr(char * s, int c)
{
    
    BEFORE_LOG("strtchr", "");

    
    char * (*old_strrchr)(char * s, int c);
    char * result;
    old_strrchr = dlsym(RTLD_NEXT, "strrchr");
    result = old_strrchr(s, c);

    
    AFTER_LOG("");

    return result;

}




size_t strspn(const char * s, const char * accept)
{
    
    BEFORE_LOG("strspn", "");

    
    size_t (*old_strspn)(const char * s, const char * accept);
    size_t result;
    old_strspn = dlsym(RTLD_NEXT, "strspn");
    result = old_strspn(s, accept);

    
    AFTER_LOG("==%lu", result);

    return result;

}




int unlink(const char * name)
{
    
    BEFORE_LOG("unlink", "");

    
    int (*old_unlink)(const char * name);
    int result;
    old_unlink = dlsym(RTLD_NEXT, "unlink");
    result = old_unlink(name);

    
    AFTER_LOG("==%d", result);

    return result;

}




int utime(const char * file, const struct utimbuf * file_times)
{
    
    BEFORE_LOG("utime", "");

    
    int (*old_utime)(const char * file, const struct utimbuf * file_times);
    int result;
    old_utime = dlsym(RTLD_NEXT, "utime");
    result = old_utime(file, file_times);

    
    AFTER_LOG("==%d", result);

    return result;

}




ssize_t write(int fd, const void * buf, size_t n)
{
    
    BEFORE_LOG("write", "");

    
    ssize_t (*old_write)(int fd, const void * buf, size_t n);
    ssize_t result;
    old_write = dlsym(RTLD_NEXT, "write");
    result = old_write(fd, buf, n);

    

    AFTER_LOG("");

    return result;

}
