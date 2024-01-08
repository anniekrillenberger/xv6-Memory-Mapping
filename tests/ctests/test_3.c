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
	    goto failed;
    }
    if (mem != (void *)addr) {
	    goto failed;
    } 
    printf(1, "poop\n");

    /* Modify something */
    char *memchar = (char*) mem;
    memchar[0] = 'a'; memchar[1] = 'a';
    
    printf(1, "peepee\n");

    /* Clean and return */
    int ret = munmap(mem, len);
    if (ret < 0) {
	    goto failed;
    }

// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
