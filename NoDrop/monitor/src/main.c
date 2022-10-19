#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <string.h>

#include "events.h"
#include "common.h"

#define PATH_FMT "/tmp/nodrop/%u-%ld.buf"
#define SECOND_IN_US 1000000000

// For AFL-SYS;
#define EXIT_SIGW_FD 250
#define EXIT_SIGR_FD 251
#define NEVENTS_SIZE sizeof(uint64_t)

static char path[100];
static struct timeval tv;
static unsigned int tid;

void nod_monitor_init(int argc, char *argv[], char *env[]) {
    gettimeofday(&tv, NULL);
    tid = (unsigned int)syscall(SYS_gettid);
    sprintf((char *)path, PATH_FMT, tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
}

static const char *__print_format[PT_UINT64 + 1][PF_OCT + 1] = {
    [PT_NONE] = {"", "", "", "", ""},/*empty*/
    [PT_INT8] = {"", "%"PRId8, "0x%"PRIx8, "%010" PRId8, "0%"PRIo8},/*PT_INT8*/
    [PT_INT16] = {"", "%"PRId16, "0x%"PRIx16, "%010" PRId16, "0%"PRIo16},/*PT_INT16*/
    [PT_INT32] = {"", "%"PRId32, "0x%"PRIx32, "%010" PRId32, "0%"PRIo32},/*PT_INT32*/
    [PT_INT64] = {"", "%"PRId64, "0x%"PRIx64, "%010" PRId64, "0%"PRIo64},/*PT_INT64*/
    [PT_UINT8] = {"", "%"PRIu8, "0x%"PRIx8, "%010" PRId8, "0%"PRIo8},/*PT_UINT8*/
    [PT_UINT16] = {"", "%"PRIu16, "0x%"PRIx16, "%010" PRIu16, "0%"PRIo16},/*PT_UINT16*/
    [PT_UINT32] = {"", "%"PRIu32, "0x%"PRIx32, "%010" PRIu32, "0%"PRIo32},/*PT_UINT32*/
    [PT_UINT64] = {"", "%"PRIu64, "0x%"PRIx64, "%010" PRIu64, "0%"PRIo64}/*PT_UINT64*/
};

// static int _parse(FILE *out, struct nod_event_hdr *hdr, char *buffer, void *__data)
// {
//     size_t i;
//     const struct nod_event_info *info;
//     const struct nod_param_info *param;
//     uint16_t *args;
//     char *data;

//     if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
//         return -1;

//     info = &g_event_info[hdr->type];
//     args = (uint16_t *)buffer;
//     data = (char *)(args + info->nparams);
    
//     fprintf(out, "%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);

//     for (i = 0; i < info->nparams; ++i) {
//         param = &info->params[i];
//         if (i > 0)  fprintf(out, ", ");
//         fprintf(out, "%s=", param->name);
//         switch(param->type) {
//         case PT_CHARBUF:
//         case PT_FSPATH:
//         case PT_FSRELPATH:
//         case PT_BYTEBUF:
//             fwrite(data, args[i], 1, out);
//             break;

//         case PT_FLAGS8:
//         case PT_UINT8:
//         case PT_SIGTYPE:
//             fprintf(out, __print_format[PT_UINT8][param->fmt], *(uint8_t *)data);
//             break;
//         case PT_FLAGS16:
//         case PT_UINT16:
//         case PT_SYSCALLID:
//             fprintf(out, __print_format[PT_UINT16][param->fmt], *(uint16_t *)data);
//             break;
        
//         case PT_FLAGS32:
//         case PT_UINT32:
//         case PT_MODE:
//         case PT_UID:
//         case PT_GID:
//         case PT_SIGSET:
//             fprintf(out, __print_format[PT_UINT32][param->fmt], *(uint32_t *)data);
//             break;
        
//         case PT_RELTIME:
//         case PT_ABSTIME:
//         case PT_UINT64:
//             fprintf(out, __print_format[PT_UINT64][param->fmt], *(uint64_t *)data);
//             break;

//         case PT_INT8:
//             fprintf(out, __print_format[PT_INT8][param->fmt], *(int8_t *)data);
//             break;

//         case PT_INT16:
//             fprintf(out, __print_format[PT_INT16][param->fmt], *(int16_t *)data);
//             break;
        
//         case PT_INT32:
//             fprintf(out, __print_format[PT_INT32][param->fmt], *(int32_t *)data);
//             break;

//         case PT_INT64:
//         case PT_ERRNO:
//         case PT_FD:
//         case PT_PID:
//             fprintf(out, __print_format[PT_INT64][param->fmt], *(int64_t *)data);
//             break;

//         default:
//             fprintf(out, "<unknown>");
//             break;
//         }

//         data += args[i];
//     }
//     fprintf(out, ")\n");
//     return 0;
// }


// borrowed from NoDrop
static int _parse(char *out, struct nod_event_hdr *hdr, char *buffer, void *__data){
    size_t i;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return -1;

    info = &g_event_info[hdr->type];
    args = (uint16_t *)buffer;
    data = (char *)(args + info->nparams);
    
    // formatting
    // fprintf(out, "%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);
    sprintf(out, "%s \n", info->name);

    return 0;
}

int nod_monitor_main(struct nod_buffer *buffer) {
    // FILE *file;
    char tmp[256];
    char *ptr, *buffer_end;
    struct nod_event_hdr *hdr;
    pid_t cur_pid;

    // if(!(file = fopen((const char *)path, "ab+"))) {
    //     perror("Cannot open log file");
    //     return 0;
    // }

    // now notify the AFL forkserver to get events number
    if(write(EXIT_SIGW_FD, &(buffer->info.nevents), NEVENTS_SIZE)!=NEVENTS_SIZE){
        printf("Not able to notice AFL forkserver.\n");
    }
    printf("Got %ld events,", buffer->info.nevents);

    ptr = buffer->buffer;
    buffer_end = buffer->buffer + buffer->info.tail;
    while (ptr < buffer_end) {
        hdr = (struct nod_event_hdr *)ptr; 
        _parse(tmp, hdr, (char *)(hdr + 1), 0);
        // send the data to forkserver
        write(EXIT_SIGW_FD, tmp, strlen(tmp)+1);
        ptr += hdr->len;
    }

    // wait for forkserver to process
    read(EXIT_SIGR_FD, &cur_pid, 4);
    printf(" exiting.\n");
    close(EXIT_SIGR_FD);

    // fclose(file);

    return 0;
}
