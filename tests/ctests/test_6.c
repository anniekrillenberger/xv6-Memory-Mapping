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

int main() { // mmap a file
    char *filename = "test_file.txt";
    int len = 100;
    char buff[len];
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED;

    /* Open a file */
    int fd = open(filename, O_CREATE | O_RDWR);
    if (fd < 0) {
        printf(1, "Error opening file\n");
	goto failed;
    }

    /* Write some data to the file */
    for (int i = 0; i < len; i++) {
        buff[i] = (char)(i % 256);
    }
    if (write(fd, buff, len) != len) {
        printf(1, "Error: Write to file FAILED\n");
	goto failed;
    }
    close(fd);

    fd = open(filename, O_CREATE | O_RDWR);
    
    /* Memory map the file */
    void *mem = mmap(0, len, prot, flags, fd, 0);
    if (mem == (void *)-1) {
        printf(1, "mmap FAILED\n");
	goto failed;
    }

    /* Verify the data in mmaped memory is the same as what was written */
    char *mem_buff = (char *)mem;
    if (my_strcmp(mem_buff, buff, len) != 0) {
        printf(1, "Couldn't read the same data back!\n");
	goto failed;
    }
    
    printf(1, "mem: %p\n", mem);
    
    // issue how mmap is returning

    /* Clean and return */
    int ret = munmap(mem, len);
    if (ret < 0) {
        printf(1, "munmap FAILED\n");
	goto failed;
    }

    close(fd);

// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
