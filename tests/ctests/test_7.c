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
    char buff[len];
    char new_buff[len];
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
        buff[i] = 'x'; 
    }
    if (write(fd, buff, len) != len) {
        printf(1, "Error: Write to file FAILED\n");
	goto failed;
    }

    /* mmap the file */
    void *mem = mmap(0, len, prot, flags, fd, 0);
    if (mem == (void *)-1) {
        printf(1, "mmap FAILED\n");
	goto failed;
    }

    /* modify in-memory contents of the mmapped region */
    char *mem_buff = (char *)mem;
    for (int i = 0; i < len; i++) {
        mem_buff[i] = 'a';     
        buff[i] = mem_buff[i]; // Later used for validating the data returned by read()
    }

    int ret = munmap(mem, len);
    if (ret < 0) {
        printf(1, "munmap FAILED\n");
	goto failed;
    }

    close(fd);

    /* Reopen the file */
    fd = open(filename, O_RDWR);
    if (fd < 0) {
        printf(1, "Error reopening file\n");
	goto failed;
    }

    /* Verify that modifications made to mmapped memory have been reflected in the file */
    if (read(fd, new_buff, len) != len) {
        printf(1, "Read from file FAILED\n");
	goto failed;
    }
    if (my_strcmp(new_buff, buff, len) != 0) {
        printf(1, "Writes to mmaped memory not reflected in file\n");
        printf(1, "\tExpected: %s\n", buff);
        printf(1, "\tGot: %s\n", new_buff);
	goto failed;
    }

    /* Clean and return */
    close(fd);

// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
