/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  RTSP Client
 *  -----------
 *  Written by Eduardo Silva P. <edsiper@gmail.com>
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* networking I/O */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

/* local headers */
#include "network.h"
#include "streamer.h"
#include "base64.h"
#include "rtsp.h"
#include "utils.h"
#include "rtcp.h"
#include "rtp.h"

/* global variables */
int rtsp_cseq;
int client_port;
int opt_verbose;
char *opt_stream;
char *opt_name;
char *stream_host;
char *dsp;
unsigned long stream_port;

void rtsp_cseq_inc()
{
    rtsp_cseq++;
}

/*
 * Returns the RTSP status code from the response, if an error occurred it
 * allocates a memory buffer and store the error message on 'error' variable
 */
int rtsp_response_status(char *response, char **error)
{
    int size = 256;
    int err_size;
    int offset = sizeof(RTSP_RESPONSE) - 1;
    char buf[8];
    char *sep;
    char *eol;
    *error = NULL;

    if (strncmp(response, RTSP_RESPONSE, offset) != 0) {
        *error = malloc(size);
        snprintf(*error, size, "Invalid RTSP response format");
        return -1;
    }

    sep = strchr(response + offset, ' ');
    if (!sep) {
        *error = malloc(size);
        snprintf(*error, size, "Invalid RTSP response format");
        return -1;
    }

    memset(buf, '\0', sizeof(buf));
    strncpy(buf, response + offset, sep - response - offset);

    eol = strchr(response, '\r');
    err_size = (eol - response) - offset - 1 - strlen(buf);
    *error = malloc(err_size + 1);
    strncpy(*error, response + offset + 1 + strlen(buf), err_size);

    return atoi(buf);
}

int rtsp_cmd_options(int sock, char *stream)
{
    int n;
    int ret = 0;
    int status;
    int size = 4096;
    char *err;
    char buf[size];

    RTSP_INFO("OPTIONS: command\n");

    memset(buf, '\0', sizeof(buf));
    n = snprintf(buf, size, CMD_OPTIONS, stream_host, stream_port, rtsp_cseq);
    DEBUG_REQ(buf);
    n = send(sock, buf, n, 0);

    RTSP_INFO("OPTIONS: request sent\n");

    memset(buf, '\0', sizeof(buf));
    n = recv(sock, buf, size - 1, 0);
    if (n <= 0) {
        printf("Error: Server did not respond properly, closing...");
        close(sock);
        exit(EXIT_FAILURE);
    }

    status = rtsp_response_status(buf, &err);
    if (status == 200) {
        RTSP_INFO("OPTIONS: response status %i (%i bytes)\n", status, n);
    }
    else {
        RTSP_INFO("OPTIONS: response status %i: %s\n", status, err);
        ret = -1;
    }

    DEBUG_RES(buf);
    rtsp_cseq_inc();

    return ret;
}

int rtsp_cmd_describe(int sock, char *stream, char **sprop)
{
    int n;
    int ret = 0;
    int status;
    int size = 4096;
    char *p, *end;
    char *err;
    char buf[size];

    RTSP_INFO("DESCRIBE: command\n");

    memset(buf, '\0', sizeof(buf));
    n = snprintf(buf, size, CMD_DESCRIBE, stream, rtsp_cseq);
    DEBUG_REQ(buf);
    n = send(sock, buf, n, 0);

    RTSP_INFO("DESCRIBE: request sent\n");

    memset(buf, '\0', sizeof(buf));
    n = recv(sock, buf, size - 1, 0);
    if (n <= 0) {
        printf("Error: Server did not respond properly, closing...");
        close(sock);
        exit(EXIT_FAILURE);
    }

    status = rtsp_response_status(buf, &err);
    if (status == 200) {
        RTSP_INFO("DESCRIBE: response status %i (%i bytes)\n", status, n);
    }
    else {
        RTSP_INFO("DESCRIBE: response status %i: %s\n", status, err);
        ret = -1;
    }

    DEBUG_RES("%s\n", buf);
    rtsp_cseq_inc();

    /* set the DSP information */
    p = strstr(buf, "\r\n\r\n");
    if (!p) {
        return -1;
    }

    /* Create buffer for DSP */
    dsp = malloc(n + 1);
    memset(dsp, '\0', n + 1);
    strcpy(dsp, p + 4);

    /* sprop-parameter-sets key */
    p = strstr(dsp, RTP_SPROP);
    if (!p) {
        return -1;
    }

    end = strchr(p, '\r');
    if (!end) {
        return -1;
    }

    int prop_size = (end - p) - sizeof(RTP_SPROP) + 1;
    *sprop = malloc(prop_size + 1);
    memcpy(*sprop, p + sizeof(RTP_SPROP) - 1, prop_size);

    return ret;
}

int rtsp_cmd_setup(int sock, char *stream, struct rtsp_session *session)
{
    int n;
    int ret = 0;
    int status;
    int field_size = 16;
    int size = 4096;
    int client_port_from = -1;
    int client_port_to = -1;
    int server_port_from = -1;
    int server_port_to = -1;
    unsigned long session_id;
    char *p;
    char *sep;
    char *err;
    char buf[size];
    char field[field_size];

    RTSP_INFO("SETUP: command\n");

    memset(buf, '\0', sizeof(buf));
    //n = snprintf(buf, size, CMD_SETUP, stream, rtsp_cseq, client_port, client_port + 1);
    n = snprintf(buf, size, CMD_SETUP, stream, rtsp_cseq);

    DEBUG_REQ(buf);
    n = send(sock, buf, n, 0);

    RTSP_INFO("SETUP: request sent\n");

    memset(buf, '\0', sizeof(buf));
    n = recv(sock, buf, size - 1, 0);
    if (n <= 0) {
        printf("Error: Server did not respond properly, closing...");
        close(sock);
        exit(EXIT_FAILURE);
    }

    status = rtsp_response_status(buf, &err);
    if (status == 200) {
        RTSP_INFO("SETUP: response status %i (%i bytes)\n", status, n);

        /* Fill session data */
        p = strstr(buf, "Transport: ");
        if (!p) {
            RTSP_INFO("SETUP: Error, Transport header not found\n");
            DEBUG_RES(buf);
            return -1;
        }

        /*
         * Commenting out this code, this part was written to support
         * RTP connection over UDP socket and determinate the server
         * ports to connect.
         *
         * By now the program is using TCP in Intervealed mode, so no
         * extra ports are required.

        buf_client_port = strstr(p, SETUP_TRNS_CLIENT);
        buf_server_port = strstr(p, SETUP_TRNS_SERVER);

        if (!buf_client_port || !buf_server_port) {
            RTSP_INFO("SETUP: Error, ports not defined in Transport header\n");
            DEBUG_RES(buf);
            return -1;
        }

         client_port from
        sep = strchr(buf_client_port + sizeof(SETUP_TRNS_CLIENT) - 1, '-');
        if (!sep) {
            RTSP_INFO("SETUP: client_port have an invalid format\n");
            DEBUG_RES(buf);
            return -1;
        }

        memset(field, '\0', sizeof(field));
        strncpy(field,
                buf_client_port + sizeof(SETUP_TRNS_CLIENT) - 1,
                sep - buf_client_port - sizeof(SETUP_TRNS_CLIENT) + 1);

        client_port_from = atoi(field);

        client_port to
        p = strchr(sep, ';');
        if (!p) {
            p = strchr(sep, '\r');
            if (!p) {
                RTSP_INFO("SETUP: client_port have an invalid format\n");
                DEBUG_RES(buf);
                return -1;
            }
        }

        memset(field, '\0', sizeof(field));
        strncpy(field, sep + 1, p - sep - 1);
        client_port_to = atoi(field);

         server_port from
        sep = strchr(buf_server_port + sizeof(SETUP_TRNS_SERVER) - 1, '-');
        if (!sep) {
            RTSP_INFO("SETUP: server_port have an invalid format\n");
            DEBUG_RES(buf);
            return -1;
        }


        memset(field, '\0', sizeof(field));
        strncpy(field,
                buf_server_port + sizeof(SETUP_TRNS_SERVER) - 1,
                sep - buf_server_port - sizeof(SETUP_TRNS_SERVER) + 1);

        server_port_from = atoi(field);

         server_port to
        p = strchr(sep, ';');
        if (!p) {
            p = strchr(sep, '\r');
            if (!p) {
                RTSP_INFO("SETUP: server_port have an invalid format\n");
                DEBUG_RES(buf);
                return -1;
            }
        }

        memset(field, '\0', sizeof(field));
        strncpy(field, sep + 1, p - sep - 1);
        server_port_to = atoi(field);
        */

        /* Session ID */
        p = strstr(buf, SETUP_SESSION);
        if (!p) {
            RTSP_INFO("SETUP: Session header not found\n");
            DEBUG_RES(buf);
            return -1;
        }

        sep = strchr(p, '\r');
        memset(field, '\0', sizeof(field));
        strncpy(field, p + sizeof(SETUP_SESSION) - 1, sep - p - sizeof(SETUP_SESSION) + 1);
        session_id = atoi(field);
    }
    else {
        RTSP_INFO("SETUP: response status %i: %s\n", status, err);
        DEBUG_RES(buf);
        return -1;
    }

    /* Fill session data */
    session->packetization = 1; /* FIXME: project specific value */
    session->cport_from = client_port_from;
    session->cport_to   = client_port_to;
    session->sport_from = server_port_from;
    session->sport_to   = server_port_to;
    session->session    = session_id;

    DEBUG_RES(buf);
    rtsp_cseq_inc();
    return ret;
}

int rtsp_cmd_play(int sock, char *stream, unsigned long session)
{
    int n;
    int ret = 0;
    int status;
    int size = 4096;
    char *err;
    char buf[size];

    RTSP_INFO("PLAY: command\n");

    memset(buf, '\0', sizeof(buf));
    n = snprintf(buf, size, CMD_PLAY, stream, rtsp_cseq, session);
    DEBUG_REQ(buf);
    n = send(sock, buf, n, 0);

    RTSP_INFO("PLAY: request sent\n");

    memset(buf, '\0', sizeof(buf));
    n = recv(sock, buf, size - 1, 0);
    if (n <= 0) {
        printf("Error: Server did not respond properly, closing...");
        close(sock);
        exit(EXIT_FAILURE);
    }

    status = rtsp_response_status(buf, &err);
    if (status == 200) {
        RTSP_INFO("PLAY: response status %i (%i bytes)\n%s\n", status, n, buf);
    }
    else {
        RTSP_INFO("PLAY: response status %i: %s\n", status, err);
        ret = -1;
    }

    DEBUG_RES(buf);
    rtsp_cseq_inc();
    return ret;
}


int rtsp_connect(char *stream)
{
    char *host;
    char *sep;
    char buf[8];
    int len;
    int pos;
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

    /* Lookup TCP port if specified */
    sep = strchr(stream + offset + 1, ':');
    if (sep) {
        pos = (sep - stream) + 1;
        sep = strchr(stream + pos, '/');
        if (!sep) {
            printf("Error: Invalid stream address '%s'\n", stream);
            exit(EXIT_FAILURE);
        }

        len = (sep - stream) - pos;
        if (len > sizeof(buf) - 1) {
            printf("Error: Invalid TCP port in stream address '%s'\n", stream);
            exit(EXIT_FAILURE);
        }

        memset(buf, '\0', sizeof(buf));
        strncpy(buf, stream + pos, len);
        stream_port = atol(buf);

    }

    stream_host = host;
    RTSP_INFO("Connecting to host '%s' port %lu...\n", stream_host, stream_port);
    return net_tcp_connect(stream_host, stream_port);
}

void rtsp_help(int status)
{
	printf("Usage: h264dec [-v] [-V] -n CHANNEL_NAME -s rtsp://stream\n\n");
	printf("  -s, --stream=URL         RTSP media stream address\n");
    printf("  -n, --name=CHANNEL_NAME  Name for local channel identifier\n");
	printf("  -h, --help               print this help\n");
	printf("  -v, --version            print version number\n");
	printf("  -V, --verbose            enable verbose mode\n");
	printf("\n");
	exit(status);
}

void rtsp_banner()
{
    printf("H264Dec v%s\n\n", VERSION);
}

void rtsp_header(int fd, int channel, uint16_t length)
{
    uint8_t tmp_8;
    uint16_t tmp_16;
    int state = 1;
    int n;

    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

    tmp_8 = 0x24;      /* RTSP magic number */
    n = send(fd, &tmp_8, 1, 0);
    printf("sent: %i\n", n);

    tmp_8 = channel;   /* channel */
    n = send(fd, &tmp_8, 1, 0);
    printf("sent: %i\n", n);

    tmp_16 = length;
    n = send(fd, &tmp_16, 2, 0);
    printf("sent: %i\n", n);

    state = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

int main(int argc, char **argv)
 {
     int fd;
     int ret;
     int opt;
     struct rtsp_session rtsp_s;

     /* defaults */
     rtsp_cseq = 1;
     stream_sock = -1;
     opt_verbose = 0;
     opt_stream = NULL;
     opt_name = NULL;
     stream_port = RTSP_PORT;
     client_port = RTSP_CLIENT_PORT;
     debug_rtcp = 1;

     static const struct option long_opts[] = {
         { "stream",  required_argument, NULL, 's' },
         { "port",    required_argument, NULL, 'p' },
         { "name",    required_argument, NULL, 'n' },
         { "version", no_argument,       NULL, 'v' },
         { "verbose", no_argument,       NULL, 'V' },
         { "help",    no_argument,       NULL, 'h' },
         { NULL, 0, NULL, 0 }
     };

     while ((opt = getopt_long(argc, argv, "s:p:n:vVh", long_opts, NULL)) != -1) {
         switch (opt) {
         case 's':
             opt_stream = strdup(optarg);
             break;
         case 'p':
             client_port = atoi(optarg);
             break;
         case 'n':
             opt_name = strdup(optarg);
             break;
         case 'v':
             rtsp_banner();
             exit(EXIT_SUCCESS);
         case 'V':
             opt_verbose = 1;
             break;
         case 'h':
             rtsp_help(EXIT_SUCCESS);
         case '?':
             rtsp_help(EXIT_FAILURE);
         }
     }


     if (!opt_stream || strncmp(opt_stream, PROTOCOL_PREFIX,
                                sizeof(PROTOCOL_PREFIX) - 1) != 0) {
         printf("Error: Invalid stream input.\n\n");
         rtsp_help(EXIT_FAILURE);
     }

     if (!opt_name) {
         printf("Error: Local channel name not specified.\n\n");
         rtsp_help(EXIT_FAILURE);
     }

     /* Connect to server */
     fd = rtsp_connect(opt_stream);
     if (fd <= 0) {
         exit(EXIT_FAILURE);
     }

     ret = rtsp_cmd_options(fd, opt_stream);
     if (ret != 0) {
         exit(EXIT_FAILURE);
     }

     char *params;
     ret = rtsp_cmd_describe(fd, opt_stream, &params);
     if (ret != 0) {
         printf("Error: Could not send DESCRIBE command to RTSP server\n");
         exit(EXIT_FAILURE);
     }

     rtsp_s.socket = fd;
     rtsp_s.stream = strdup(opt_stream);

     rtsp_cmd_setup(fd, opt_stream, &rtsp_s);
     rtsp_cmd_play(fd, opt_stream, rtsp_s.session);

     /* H264 Parameters, taken from the SDP output */
     int p_size;
     char *sep;
     char *sps;
     char *pps;
     unsigned char *sps_dec;
     unsigned char *pps_dec;
     size_t sps_len;
     size_t pps_len;

     /* SPS */
     sep = strchr(params, ',');
     p_size = (sep - params);
     sps = malloc(p_size + 1);
     memset(sps, '\0', p_size + 1);
     memcpy(sps, params, p_size);

     /* PPS */
     p_size = (strlen(params) - p_size);
     pps = malloc(p_size + 1);
     memset(pps, '\0', p_size + 1);
     memcpy(pps, sep + 1, p_size);

     /* Decode each parameter */
     sps_dec = base64_decode((const unsigned char *) sps, strlen(sps), &sps_len);
     pps_dec = base64_decode((const unsigned char *) pps, strlen(pps), &pps_len);

     int channel;
     int base;
     struct rtp_header rtp_h;
     int r;
     int max_buf_size = 65536 * 4;
     unsigned char raw[max_buf_size];
     unsigned char raw_tmp[max_buf_size];
     unsigned char payload[max_buf_size];
     unsigned int raw_length;
     unsigned int raw_offset = 0;
     unsigned int rtp_length;
     unsigned int paysize;
     int data;
     int rtp_count = 0;
     int rtp_first_seq = -1;
     int rtp_highest_seq = 0;
     int rtcp_last_sr_ts = 0;

     data = open("video.h264", O_CREAT|O_WRONLY|O_TRUNC, 0666);

     uint8_t nal_header[4] = {0x00, 0x00, 0x00, 0x01};

     /* [00 00 00 01] [SPS] */
     write(data, &nal_header, sizeof(nal_header));
     write(data, sps_dec, sps_len);

     /* [00 00 00 01] [PPS] */
     write(data, &nal_header, sizeof(nal_header));
     write(data, pps_dec, pps_len);

     /* Create unix named pipe */
     stream_sock = streamer_prepare(opt_name, sps_dec, sps_len, pps_dec, pps_len);
     if (stream_sock <= 0) {
         printf("Error: could not create unix socket\n\n");
         exit(EXIT_FAILURE);
     }

     /* Local pipe */
     streamer_pipe_init(stream_pipe);
     streamer_loop(stream_sock);

     printf("Streaming will start in 5 seconds...\n");
     //sleep(5);

     while (1) {
         raw_offset = 0;
         raw_length = 0;
         memset(raw, '\0', sizeof(raw));

     read_pending:

         /* is buffer full ? */
         if (raw_length >= max_buf_size) {
             printf(">> RESETTING\n");

             if (raw_offset < raw_length - 1) {
                 int bytes = raw_length - raw_offset;

                 memset(raw_tmp, '\0', sizeof(raw_tmp));
                 memcpy(raw_tmp, raw + raw_offset, bytes);

                 memset(raw, '\0', sizeof(raw));
                 memcpy(raw, raw_tmp, bytes);

                printf("   Move:  %i\n", raw_length - raw_offset);
                raw_length = bytes;
                raw_offset = 0;
                base = 0;
                if (raw[raw_offset] != 0x24) {
                    printf("MASTER CORRUPTION\n");
                }

            }
            else {
                raw_length = 0;
                memset(raw, '\0', sizeof(raw));
            }
            //exit(0);
         }

         /* read incoming data */
         printf("TRYING TO READ %i\n", max_buf_size - raw_length);
         r = recv(fd, raw + raw_length, max_buf_size - raw_length, 0);
         printf(">> READ: %i (up to %i)\n", r, max_buf_size - raw_length);

         if (r <= 0) {
            printf("READ IS ZERO!");
            perror("recv");
            exit(1);
            continue;
        }

        raw_length += r;

        /* parse all data in our buffer */
        while (raw_offset < raw_length) {

            /* RTSP Interleaved header */
            if (raw[raw_offset] == 0x24) {
                channel = raw[raw_offset + 1];
                rtp_length  = raw[raw_offset + 2] * 256 + raw[raw_offset + 3];


                printf(">> RTSP Interleaved (offset = %i/%i)\n",
                       raw_offset, raw_length);
                printf("   Magic         : 0x24\n");
                printf("   Channel       : %i\n", channel);
                printf("   Payload Length: %i\n", rtp_length);

                /* RTSP header is 4 bytes, update the offset */
                raw_offset += 4;

                if (rtp_length > (raw_length - raw_offset)) {
                    raw_offset -= 4;
                    printf("[CH %i] PENDING: RTP_LENGTH=%i ; RAW_LENGTH=%i; RAW_OFFSET=%i\n",
                           channel, rtp_length, raw_length, raw_offset);
                    goto read_pending;
                }

                /* RTCP data */
                if (channel >= 1) {
                    int idx;
                    int rtcp_count;
                    struct rtcp_pkg *rtcp;

                    /* Decode RTCP packet(s) */
                    rtcp = rtcp_decode(raw + raw_offset, rtp_length, &rtcp_count);

                    /* For each RTCP packet, send a reply */
                    for (idx = 0; idx < rtcp_count; idx++) {
                        /* sender report, send a receiver report */
                        if (rtcp[idx].type == RTCP_SR) {
                            rtsp_header(fd, 1, 32);
                            rtcp_receiver_report(fd,
                                                 RTCP_SSRC,
                                                 rtp_count,
                                                 rtp_first_seq,
                                                 rtp_highest_seq,
                                                 rtcp_last_sr_ts);
                        }
                    }
                    raw_offset += rtp_length;
                    continue;
                }

                if (rtp_length == 0) {
                    continue;
                }

                base = raw_offset;

                /*
                 * Channel 0
                 * ---------
                 * If the channel is zero, the payload should contain RTP data,
                 * we need to identify the RTP header fields so later we can
                 * proceed to extract the H264 information.
                 */
                rtp_h.version = raw[raw_offset] >> 6;
                rtp_h.padding = CHECK_BIT(raw[raw_offset], 5);
                rtp_h.extension = CHECK_BIT(raw[raw_offset], 4);
                rtp_h.cc = raw[raw_offset] & 0xFF;

                /* next byte */
                raw_offset++;

                rtp_h.marker = CHECK_BIT(raw[raw_offset], 8);
                rtp_h.pt     = raw[raw_offset] & 0x7f;

                /* next byte */
                raw_offset++;

                /* Sequence number */
                rtp_h.seq = raw[raw_offset] * 256 + raw[raw_offset + 1];
                raw_offset += 2;

                /* time stamp */
                memcpy(&rtp_h.ts, raw + raw_offset, 4);
                raw_offset += 4;

                /* ssrc */
                memcpy(&rtp_h.ssrc, raw + raw_offset, 4);
                raw_offset += 4;

                /* Payload size */
                paysize = rtp_length - (raw_offset - base);

                memset(payload, '\0', sizeof(payload));
                memcpy(&payload, raw + raw_offset, paysize);

                /* Update counters */
                rtp_count++;
                if (rtp_h.seq > rtp_highest_seq) {
                    rtp_highest_seq = rtp_h.seq;
                }

                if (rtp_first_seq == -1) {
                    rtp_first_seq = rtp_h.seq;
                }

                /* Display RTP header info */
                printf("   >> RTP\n");


                /* Payload Debug

                printf("      =============PAYLOAD===============\n");
                int y;
                int c =0;
                for (y=0; y < paysize; y++) {
                    if (c == 0) { printf("      ");}
                    if (c == 8) { printf("\n      ");}
                    c++;
                    printf("%X ", payload[y]);
                }
                printf("\n      =================================\n");
                */
                printf("      Version     : %i\n", rtp_h.version);
                printf("      Padding     : %i\n", rtp_h.padding);
                printf("      Extension   : %i\n", rtp_h.extension);
                printf("      CSRC Count  : %i\n", rtp_h.cc);
                printf("      Marker      : %i\n", rtp_h.marker);
                printf("      Payload Type: %i\n", rtp_h.pt);
                printf("      Sequence    : %i\n", rtp_h.seq);
                printf("      Timestamp   : %u\n", rtp_h.ts);
                printf("      Sync Source : %u\n", rtp_h.ssrc);

                /*
                 * NAL, first byte header
                 *
                 *   +---------------+
                 *   |0|1|2|3|4|5|6|7|
                 *   +-+-+-+-+-+-+-+-+
                 *   |F|NRI|  Type   |
                 *   +---------------+
                 */
                int nal_forbidden_zero = CHECK_BIT(payload[0], 7);
                int nal_nri  = (payload[0] & 0x60) >> 5;
                int nal_type = (payload[0] & 0x1F);

                printf("      >> NAL\n");
                printf("         Forbidden zero: %i\n", nal_forbidden_zero);
                printf("         NRI           : %i\n", nal_nri);
                printf("         Type          : %i\n", nal_type);

                /* Single NAL unit packet */
                if (nal_type >= NAL_TYPE_SINGLE_NAL_MIN &&
                    nal_type <= NAL_TYPE_SINGLE_NAL_MAX) {

                    /* Write NAL header */
                    write(data, nal_header, sizeof(nal_header));
                    streamer_write_nal();

                    /* Write NAL unit */
                    write(data, payload, paysize);
                    streamer_write(payload, sizeof(paysize));
                }
                /* Aggregation packet */
                else if (nal_type == NAL_TYPE_STAP_A) {
                    uint8_t *p, *p_end;
                    uint8_t *q, *q_end;
                    uint16_t tmp_nal_size;

                    p = raw + raw_offset;
                    p_end = raw + rtp_length;
                    q = payload + 1;
                    q_end = payload + paysize;

                    while (q < q_end && p < p_end) {
                        write(data, nal_header, sizeof(nal_header));
                        streamer_write_nal();

                        tmp_nal_size = (*q << 8) | *(q + 1);
                        printf("tmp_nal_size=%i cmp %i\n",
                               tmp_nal_size,
                               (*q << 8) | *(q + 1));
                        q += 2;

                        write(data, q, tmp_nal_size);
                        streamer_write(q, tmp_nal_size);
                        q += tmp_nal_size;
                    }
                }
                else if (nal_type == NAL_TYPE_FU_A) {
                    printf("         >> Fragmentation Unit\n");

                    unsigned int n;
                    uint8_t *q;
                    q = payload;

                    uint8_t h264_start_bit = q[1] & 0x80; //CHECK_BIT(q[1], 7); // & 0x80;
                    uint8_t h264_end_bit   = q[1] & 0x40; //CHECK_BIT(q[1], 6); // & 0x40;
                    uint8_t h264_type      = q[1] & 0x1F;
                    uint8_t h264_nri       = (q[0] & 0x60) >> 5;
                    uint8_t h264_key       = (h264_nri << 5) | h264_type;

                    if (h264_start_bit) {
                        /* write NAL header */
                        write(data, &nal_header, sizeof(nal_header));
                        streamer_write_nal();

                        /* write NAL unit code */
                        write(data, &h264_key, sizeof(h264_key));
                        streamer_write(&h264_key, sizeof(h264_key));
                    }

                    n = write(data, q + 2, paysize - 2);
                    streamer_write(q + 2, paysize - 2);

                    if (h264_end_bit) {
                        /* nothing to do... */
                    }

                    printf("            Wrote: %i, start bit: %i  end bit: %i\n",
                           n, h264_start_bit, h264_end_bit);
                }
                else {
                    printf("OTHER NAL!: %i\n", nal_type);
                    exit(1);
                    raw_offset++;
                    continue;
                }

                raw_offset += paysize;
                continue;
            }
            raw_offset++;
        }
        continue;
    }
    close(data);

    return 0;
}
