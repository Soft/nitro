#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#define PATH "/proc/cpuinfo"

int main(void) {
    struct stat stat_buf;
    if (stat(PATH, &stat_buf) < 0) {
         perror("stat failed");
         return EXIT_FAILURE;
    }
    printf("%lu", stat_buf.st_dev);
    return EXIT_SUCCESS;
}
