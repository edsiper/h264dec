/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  RTSP Client
 *  -----------
 *  Written by Eduardo Silva P. <edsiper@gmail.com>
 */

/* generic headers */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* local headers */
#include "rtsp.h"
#include "network.h"
#include "utils.h"

int rtp_connect(char *stream)
{
    char *host;
    char *sep;
    int len;
    int offset = sizeof(PROTOCOL_PREFIX) - 1;

    /* Lookup the host address */
    if (!(sep = strchr(stream + offset, ':'))) {
        sep = strchr(stream + offset, '/');
    }

    if (!sep) {
        printf("Error: Invalid stream address '%s'", stream);
        exit(EXIT_FAILURE);
    }
    len = (sep - stream) - offset;
    host = malloc(len + 1);
    strncpy(host, stream + offset, len);
    host[len] = '\0';

    RTP_INFO("Connecting to host '%s' port %i...\n", host, 0);

    return net_udp_connect(host, 0);
}

/*
 * In order to initialize the RTP session it requires a
 * a previous RTSP session with basic SDP information
 */
void rtp_init(struct rtsp_session *rtsp_info)
{


}
