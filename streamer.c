/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "network.h"
#include "streamer.h"

/*
 * Register stream data into local file system, create the unix
 * socket and return the file descriptor.
 */
int streamer_prepare(const char *name,
                     unsigned char *sps, int sps_len,
                     unsigned char *pps, int pps_len)
{
    int fd;
    int size = 128;
    char path_sock[size];
    char path_meta[size];
    uint8_t nal_header[4] = {0x00, 0x00, 0x00, 0x01};

    snprintf(path_sock, size, "/tmp/%s.h264s.sock", name);
    snprintf(path_meta, size, "/tmp/%s.h264s.meta", name);

    /* write metadata file */
    fd = open(path_meta, O_CREAT|O_WRONLY|O_TRUNC, 0666);
    write(fd, &nal_header, sizeof(nal_header));
    write(fd, sps, sps_len);
    write(fd, &nal_header, sizeof(nal_header));
    write(fd, pps, pps_len);
    close(fd);

    /* create unix sock */
    fd = net_unix_sock(path_sock);

    return fd;
}

/*
 * Create the local Pipe, this pipe is used to transfer the
 * extracted H264 data to the unix socket. It also takes care
 * to increase the pipe buffer size.
 */
int streamer_pipe_init(int pipefd[2])
{
    int fd;
    int ret;
    int size = 64;
    long pipe_max;
    char buf[size];

    /* create pipe */
    ret = pipe(pipefd);
    if (ret != 0) {
        printf("Error: could not create streamer pipe\n");
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    /* Get maximum pipe buffer size allowed by the kernel */
    fd = open("/proc/sys/fs/pipe-max-size", O_RDONLY);
    if (fd <= 0) {
        printf("Warning: could not open pipe-max-size");
        perror("open");
        exit(EXIT_FAILURE);
    }

    ret = read(fd, buf, size);
    if (ret <= 0) {
        printf("Warning: could not read pipe-max-size value");
        perror("read");
        exit(EXIT_FAILURE);
    }

    close(fd);

    pipe_max = atol(buf);
    ret = fcntl(pipefd[1], F_SETPIPE_SZ, pipe_max);

    if (ret == -1) {
        printf("Warning: could not increase pipe limit to %lu\n", pipe_max);
        exit(EXIT_FAILURE);
    }

    return 0;
}
