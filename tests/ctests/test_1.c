#include "types.h"
#include "user.h"
#include "stat.h"
#include "mmap.h"

int main() {
    uint addr = 0x60020000;
    int len = 4000;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANON | MAP_FIXED | MAP_SHARED;
    int fd = -1;

    /* mmap anon memory */
    void *mem = mmap((void *)addr, len, prot, flags, fd, 0);
    
    if (mem == (void *)-1) {
        printf(1, "mem == (void *)-1\n");
	goto failed;
    }
    if (mem != (void *)addr) {
        printf(1, "mem != (void *)addr\n");
	goto failed;
    } 

// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "mem: %p\n", mem);
    printf(1, "MMAP\t FAILED\n");
    exit();
}
