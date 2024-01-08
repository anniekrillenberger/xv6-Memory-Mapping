#include "types.h"
#include "user.h"
#include "stat.h"
#include "mmap.h"

int main() { // try to allocate memory with MAP_FIXED at an illegal address
    uint addr = 0x40000000;
    int len = 4000;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANON | MAP_FIXED | MAP_SHARED;
    int fd = -1;

    /* mmap anon memory */
    void *mem = mmap((void *)addr, len, prot, flags, fd, 0);
    if (mem != (void *)-1) {
	goto failed;
    }

// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
