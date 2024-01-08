#include "types.h"
#include "user.h"
#include "stat.h"
#include "mmap.h"
#include "fcntl.h"

int my_strcmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 1;
        }
    }
    return 0;
}

int main() { // Try growing memory without MAP_GROWSUP - should segfault
    int len = 4000;
    int extra = 1000;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANON | MAP_SHARED;
    //void *addr = 0x60000000;
    int fd = -1;

    /* mmap anon memory */
    void *mem = mmap(0, len, prot, flags, fd, 0);
    if (mem == (void *)-1) {
        printf(1, "mmap FAILED\n");
	goto failed;
    }

    /* Fill the memory with data */
    char *buff = (char *)malloc((len + extra) * sizeof(char));
    char *mem_buff = (char *)mem;
    for (int i = 0; i < (len + extra); i++) {
        mem_buff[i] = (char)(i % 256);
        buff[i] = mem_buff[i];
    }

    /* A segmentation fault must happen in the above for loop */
    printf(1, "Expected SegFault\n");
    goto failed;


    /* Clean and return */
    int ret = munmap(mem, len);
    if (ret < 0) {
        printf(1, "munmap FAILED\n");
	goto failed;
    }
    free(buff);



// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
