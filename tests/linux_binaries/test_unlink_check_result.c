#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

/*
This test binary creates a files, removes it and then checks if the file was
truly removed. This is useful for testing system call bypass functionality: we
can try to bypass the unlink system call and check if the file was really
deleted.
*/

#define PATH "/tmp/test_unlink_check_result.tmp"

#define EXIT_FILE_EXISTS 100
#define EXIT_FILE_NOT_FOUND 200

int main(void) {
    struct stat stat_buf;
    int fd = open(PATH, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
    if (fd < 0) {
        perror("open failed");
        return EXIT_FAILURE;
    }
    if (close(fd) < 0) {
        perror("close failed");
        return EXIT_FAILURE;
    }
    if (unlink(PATH) < 0) {
        perror("unlink failed");
        return EXIT_FAILURE;
    }
    if (stat(PATH, &stat_buf) == 0) {
        fputs(PATH " exists\n", stdout);
        return EXIT_FILE_EXISTS;
    } else {
        if (errno == ENOENT) {
            fputs(PATH " does not exist\n", stdout);
            return EXIT_FILE_NOT_FOUND;
        } else {
            perror("stat failed");
            return EXIT_FAILURE;
        }
    }
}
