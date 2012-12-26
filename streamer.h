/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef STREAMER_H
#define STREAMER_H

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	1031
#endif

int streamer_prepare(const char *name,
                     unsigned char *sps, int sps_len,
                     unsigned char *pps, int pps_len);
int streamer_pipe_init(int pipefd[2]);

#endif
