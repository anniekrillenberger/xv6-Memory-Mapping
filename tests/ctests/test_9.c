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

int main() { // MAP_GROWSUP with file-backed mapping
    char *filename = "test_file.txt";
    int len = 4000;
    int extra = 1000;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED | MAP_GROWSUP;

    char *buff = (char *)malloc((len + extra) * sizeof(char));

    /* Open the file */
    int fd = open(filename, O_CREATE | O_RDWR);
    if (fd < 0) {
        printf(1, "Error opening file\n");
	goto failed;
    }

    /* mmap anon memory */
    void *mem = mmap(0, len, prot, flags, fd, 0);
    if (mem == (void *)-1) {
        printf(1, "mmap FAILED\n");
	goto failed;
    }

    /* Fill the memory with data */
    char *mem_buff = (char *)mem;
    for (int i = 0; i < (len + extra); i++) {
        if (i < len)
            mem_buff[i] = 'a';
        else
            mem_buff[i] = 'z';
        buff[i] = mem_buff[i];
    }

    /* See if those values have been actually written */
    if (my_strcmp(mem_buff, buff, (len + extra)) != 0) {
        printf(1, "Couldn't read the same data back!\n");
        printf(1, "Expected: %s\n", buff);
        printf(1, "Got: %s\n", mem_buff);
	goto failed;
    }

    /* Clean and return */
    int ret = munmap(mem, len + extra);
    if (ret < 0) {
        printf(1, "munmap FAILED\n");
	goto failed;
    }
    close(fd);

    /* Reopen the file */
    fd = open(filename, O_RDWR);
    if (fd < 0) {
        printf(1, "Error opening file\n");
	goto failed;
    }

    /* Verify that modifications made to mmapped memory have been reflected in the file */
    char *new_buff = (char *)malloc((len + extra) * sizeof(char));
    if (read(fd, new_buff, (len + extra)) != (len + extra)) {
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
    free(buff);
    free(new_buff);


// success:
    printf(1, "MMAP\t SUCCESS\n");
    exit();

failed:
    printf(1, "MMAP\t FAILED\n");
    exit();
}
