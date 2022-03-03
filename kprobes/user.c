#define _XOPEN_SOURCE 700
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* uintmax_t */
#include <string.h>
#include <sys/mman.h>
#include <unistd.h> /* sysconf */


/* Format documented at:
 * https://github.com/torvalds/linux/blob/v4.9/Documentation/vm/pagemap.txt
 */
typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return                0 for success, 1 for failure
 */

 int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr)
{
    size_t nread;
    ssize_t ret;
    uint64_t data;

    nread = 0;
    while (nread < sizeof(data)) {
        ret = pread(pagemap_fd, ((uint8_t*)&data) + nread, sizeof(data),
                (vaddr / sysconf(_SC_PAGE_SIZE)) * sizeof(data) + nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 54) - 1);
    entry->soft_dirty = (data >> 54) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[out] paddr physical address
 * @param[in]  pid   process to convert for
 * @param[in] vaddr  virtual address to get entry for
 * @return           0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr)
{
    char pagemap_file[BUFSIZ];
    int pagemap_fd;

    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        return 1;
    }
    close(pagemap_fd);
    *paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

// enum { BUFFER_SIZE = 12800 };
long Length = 128;

int main(int argc, char **argv)
{
    // int fd;
    // char *address1, *address2;
    // // char buf[BUFFER_SIZE];
    // char buf[Length];
    // uintptr_t paddr;
    
    // fd = open("/proc/lkmc_mmap", O_RDWR | O_SYNC);
    // if (fd < 0) {
    //     perror("open");
    //     assert(0);
    // }
    // printf("fd = %d\n", fd);

    // /* mmap twice for double fun. */
    // // long page_size;
    // // page_size = sysconf(_SC_PAGE_SIZE);
    // // puts("mmap 1");
    // // address1 = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    // address1 = mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    // if (address1 == MAP_FAILED) {
    //     perror("mmap");
    //     assert(0);
    // }

    // int i=0 ;
    // while(1){
    //     read(fd, buf, Length);
    //     i = i%32;
    //     printf("it is %s", (address1 + (Length * i)));
    //     //printf("it is %d", ((BUFFER_SIZE * i) & (BUFFER_SIZE -1)));
    //     i++;
    // }

    // // read(fd, buf, Length);
    // // printf("ALL CONTENT:\n %s", address1);

    // puts("munmap 1");
    // if (munmap(address1, Length)) {
    //     perror("munmap");
    //     assert(0);
    // }
    // puts("close");
    // close(fd);

    int device_fd = open("/dev/test", O_RDWR); 
    if (device_fd < 0){
        perror("Failed to open the device...");
        exit(1);
    }
    ioctl(device_fd, 0);

    return EXIT_SUCCESS;
}
