#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <inttypes.h>

#include "export.h"


static int _parse(FILE *out, struct nod_event_hdr *hdr, char *buffer, void *__data)
{
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
    fprintf(out, "%s", info->name);

    // // add param info
    // for (i = 0; i < info->nparams; ++i) {
    //     param = &info->params[i];
    //     if (i > 0)  fprintf(out, ", ");
    //     fprintf(out, "%s=", param->name);
    //     switch(param->type) {
    //     case PT_CHARBUF:
    //     case PT_FSPATH:
    //     case PT_FSRELPATH:
    //     case PT_BYTEBUF:
    //         fwrite(data, args[i], 1, out);
    //         break;

    //     case PT_FLAGS8:
    //     case PT_UINT8:
    //     case PT_SIGTYPE:
    //         fprintf(out, __print_format[PT_UINT8][param->fmt], *(uint8_t *)data);
    //         break;
    //     case PT_FLAGS16:
    //     case PT_UINT16:
    //     case PT_SYSCALLID:
    //         fprintf(out, __print_format[PT_UINT16][param->fmt], *(uint16_t *)data);
    //         break;
        
    //     case PT_FLAGS32:
    //     case PT_UINT32:
    //     case PT_MODE:
    //     case PT_UID:
    //     case PT_GID:
    //     case PT_SIGSET:
    //         fprintf(out, __print_format[PT_UINT32][param->fmt], *(uint32_t *)data);
    //         break;
        
    //     case PT_RELTIME:
    //     case PT_ABSTIME:
    //     case PT_UINT64:
    //         fprintf(out, __print_format[PT_UINT64][param->fmt], *(uint64_t *)data);
    //         break;

    //     case PT_INT8:
    //         fprintf(out, __print_format[PT_INT8][param->fmt], *(int8_t *)data);
    //         break;

    //     case PT_INT16:
    //         fprintf(out, __print_format[PT_INT16][param->fmt], *(int16_t *)data);
    //         break;
        
    //     case PT_INT32:
    //         fprintf(out, __print_format[PT_INT32][param->fmt], *(int32_t *)data);
    //         break;

    //     case PT_INT64:
    //     case PT_ERRNO:
    //     case PT_FD:
    //     case PT_PID:
    //         fprintf(out, __print_format[PT_INT64][param->fmt], *(int64_t *)data);
    //         break;

    //     default:
    //         fprintf(out, "<unknown>");
    //         break;
    //     }

    //     data += args[i];
    // }
    fprintf(out, ")\n");

    return 0;
}

int main(int argc, char *argv[]) {
    int fd;
    int ret;
    FILE *file;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [clean|fetch|start|stop|count]\n", argv[0]);
        return 0;
    }

    fd = open(NOD_IOCTL_PATH, O_RDWR);
    if (fd < 0) {
        perror("Cannot open " NOD_IOCTL_PATH);
        return 127;
    }

    // AFL-SYS new ioctl function
    if (!strcmp(argv[1], "clean")) {
        if (!ioctl(fd, NOD_IOCTL_CLEAR_GLOBAL_BUFFER, 0))
            fprintf(stderr, "Success\n");
    } else if (!strcmp(argv[1], "fetch")) {
        if ((ret = ioctl(fd, NOD_IOCTL_READ_GLOBAL_BUFFER_COUNT_INFO, &cinfo))) {
            fprintf(stderr, "Get Buffer Count Info failed, reason %d\n", ret);
            return -1;
        }

        if (cinfo.unflushed_len < 1) {
            return 0;
        }

        fetch.len = cinfo.unflushed_len;
        fetch.buf = malloc(fetch.len);
        if (!fetch.buf) {
            fprintf(stderr, "Allocate memory failed\n");
            return -1;
        }

        printf("Event number: %d, Unflushed length: %d \n", 
            cinfo.unflushed_count, cinfo.unflushed_len);

        if ((ret = ioctl(fd, NOD_IOCTL_FETCH_GLOBAL_BUFFER, &fetch))) {
            fprintf(stderr, "Fetch Global Buffer failed, reason %d\n", ret);
            return -1;
        }

        if (argc <= 2) file = stdout;
        else file = fopen(argv[2], "wb");
        if (!file) {
            fprintf(stderr, "Cannot open file\n");
            return -1;
        }

        // added from main.c to process raw data 
        struct nod_event_hdr *hdr;
        char *ptr, *buffer_end;
        ptr = fetch.buf;
        buffer_end = fetch.buf + fetch.len;
        while (ptr < buffer_end) {
            hdr = (struct nod_event_hdr *)ptr; 
            _parse(file, hdr, (char *)(hdr + 1), 0);
            // fwrite(ptr, hdr->len, 1, file);
            ptr += hdr->len;

        }

        // if (fwrite(fetch.buf, fetch.len, 1, file) == 1) {
        //     fprintf(stderr, "Write %lu bytes to file %s\n", fetch.len, argc <= 2 ? "stdout" : argv[2]);
        // } else {
        //     fprintf(stderr, "Write to file %s failed\n", argc <= 2 ? "stdout" : argv[2]);
        // }

        if (file != stdout)
            fclose(file);

    } else if (!strcmp(argv[1], "count")) {
        if (!ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &cinfo)) {
            printf("event_count=%lu,unflushed_count=%lu,unflushed_len=%lu\n", cinfo.event_count, cinfo.unflushed_count, cinfo.unflushed_len);
        }
    } else if (!strcmp(argv[1], "stop")) {
        if (!ioctl(fd, NOD_IOCTL_STOP_RECORDING, 0))
            fprintf(stderr, "Stopped\n");

    } else if (!strcmp(argv[1], "start")) {
        if (!ioctl(fd, NOD_IOCTL_START_RECORDING, 0))
            fprintf(stderr, "Start\n");

    } else {
        fprintf(stderr, "Unknown cmd %s\n", argv[1]);
    }

    return 0;
}
