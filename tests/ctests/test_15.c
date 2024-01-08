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

int main() {
    char *filename = "test_file.txt";
    int len = 100;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE;
    char buff[len];
    char new_buff[len];

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

    /* mmap the file */
    printf(1, "about to mmap\n");
    void *mem = mmap(0, len, prot, flags, fd, 0);
    if (mem == (void *)-1) {
        printf(1, "mmap FAILED\n");
        goto failed;
    }

    /* Moify the mmapped memory */
    char *charmem = (char*)mem;
    for(int i = 0; i < len; i++) {
	    charmem[i] = 'a';
    	    new_buff[i] = charmem[i];
	}

    /* Fork */
    int pid = fork();
    if (pid == 0) {
        /* Verify the child can read the same data */
        char *mem_buff = (char *)mem;
        if (my_strcmp(mem_buff, new_buff, len) != 0) {
            printf(1, "Data mismatch in child\n");
            goto failed;
        }

	/* Modify data in child - shouldn't affect parent */
	for(int i = 0; i < len; i++)
		mem_buff[i] = 'b';

	/* Child success - exit */
	exit();
    } else {
        wait();

	/* Verify the child modifications are not seen by the parent */
	char *mem_buff = (char*)mem;
	if(my_strcmp(mem_buff, new_buff, len) != 0) {
		printf(1, "Parent data corrupted by child\n");
		goto failed;
	}

        /* Clean and return */
        printf(1, "about to munmap\n");
        int ret = munmap(mem, len);
        if (ret < 0) {
            printf(1, "munmap failed\n");
            goto failed;
        }

        close(fd);
    }




// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
