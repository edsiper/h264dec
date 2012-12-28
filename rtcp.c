/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  RTCP
 *  ----
 *  Written by Eduardo Silva P. <edsiper@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "rtcp.h"

/*
 * Decode a RTSP payload and strip the RTCP frames, it returns an array of
 * rtcp_pkg struct and set the number of entries in count variable
 */
struct rtcp_pkg *rtcp_decode(unsigned char *payload,
                             unsigned long len, int *count)
{
    int i = 0;
    int start = 0;
    int idx = 0;
    *count = 0;

    /*
     * We define a maximum of 16 RTCP packets to decode, rarely
     * we will have more than two.
     */
    struct rtcp_pkg *pk = malloc(sizeof(struct rtcp_pkg) * 16);

    while (i < len) {
        start = i;

        /* Decode RTCP */
        pk[idx].version   = (payload[i] >> 6);
        pk[idx].padding   = (payload[i] & 0x20) >> 5;
        pk[idx].extension = (payload[i] & 0x10) >> 4;
        pk[idx].ccrc      = (payload[i] & 0xF);

        i++;
        pk[idx].type      = (payload[i]);

        /* length */
        i++;
        pk[idx].length    = (payload[i] * 256);
        i++;
        pk[idx].length   += payload[i];

        if (debug_rtcp) {
            printf("RTCP Version  : %i\n", pk[idx].version);
            printf("     Padding  : %i\n", pk[idx].padding);
            printf("     Extension: %i\n", pk[idx].extension);
            printf("     CCRC     : %i\n", pk[idx].ccrc);
            printf("     Type     : %i\n", pk[idx].type);
            printf("     Length   : %i (%i bytes)\n",
                   pk[idx].length, (pk[idx].length + 1) * 4);
        }

        /* server report */
        if (pk[idx].type == RTCP_SR) {
            pk[idx].ssrc    = (
                               (payload[i + 4]) |
                               (payload[i + 3] <<  8) |
                               (payload[i + 2] << 16) |
                               (payload[i + 1] << 24)
                               );

            pk[idx].ts_msw  =  (
                                (payload[i + 8]) |
                                (payload[i + 7] <<  8) |
                                (payload[i + 6] << 16) |
                                (payload[i + 5] << 24)
                                );

            pk[idx].ts_lsw  =  (
                                (payload[i + 12]) |
                                (payload[i + 11] <<  8) |
                                (payload[i + 10] << 16) |
                                (payload[i +  9] << 24)
                                );

            pk[idx].ts_rtp  =  (
                                (payload[i + 16]) |
                                (payload[i + 15] <<  8) |
                                (payload[i + 14] << 16) |
                                (payload[i + 13] << 24)
                                );

            pk[idx].sd_pk_c =  (
                                (payload[i + 20]) |
                                (payload[i + 19] <<  8) |
                                (payload[i + 18] << 16) |
                                (payload[i + 17] << 24)
                                );

            pk[idx].sd_pk_c =  (
                                (payload[i + 24]) |
                                (payload[i + 23] <<  8) |
                                (payload[i + 22] << 16) |
                                (payload[i + 21] << 24)
                                );
            i += 24;

            if (debug_rtcp) {
                printf("     SSRC     : 0x%x (%u)\n",
                       pk[idx].ssrc, pk[idx].ssrc);
                printf("     TS MSW   : 0x%x (%u)\n",
                       pk[idx].ts_msw, pk[idx].ts_msw);
                printf("     TS LSW   : 0x%x (%u)\n",
                       pk[idx].ts_lsw, pk[idx].ts_lsw);
                printf("     TS RTP   : 0x%x (%u)\n",
                       pk[idx].ts_rtp, pk[idx].ts_rtp);
                printf("     SD PK CT : %u\n", pk[idx].sd_pk_c);
                printf("     SD OC CT : %u\n", pk[idx].sd_oc_c);
            }
        }
        /* source definition */
        else if (pk[idx].type == RTCP_SDES) {
            pk[idx].identifier = (
                                  (payload[i + 4]) |
                                  (payload[i + 3] <<  8) |
                                  (payload[i + 2] << 16) |
                                  (payload[i + 1] << 24)
                                  );
            i += 5;
            pk[idx].sdes_type = payload[i];

            i++;
            pk[idx].sdes_length = payload[i];

            /* we skip the source name, we dont need it */
            i += pk[idx].sdes_length;

            /* end ? */
            i++;
            pk[idx].sdes_type2 = payload[i];

            i++;
            if (debug_rtcp) {
                printf("     ID       : %u\n", pk[idx].identifier);
                printf("     Type     : %i\n", pk[idx].sdes_type);
                printf("     Length   : %i\n", pk[idx].sdes_length);
                printf("     Type 2   : %i\n", pk[idx].sdes_type2);
            }
       }

        if (debug_rtcp) {
            printf("     Len Check: ");
            if ( (i - start) / 4 != pk[idx].length) {
                printf("Error\n");
            }
            else {
                printf("OK\n");
            }
        }
        /* Discard packet */
        else {
            i += pk[idx].length;
        }
        i++;
        idx++;
    }

    *count = idx;
    return pk;
}

/* create a receiver report package */
int rtcp_receiver_report(int fd,
                         uint32_t identifier,
                         unsigned int rtp_count,
                         unsigned int rtp_first_seq,
                         unsigned int rtp_highest_seq,
                         unsigned int rtcp_last_sr_ts)
{
    uint8_t  tmp_8;
    uint16_t tmp_16;
    uint32_t tmp_32;
    int state = 1;

    /* Enable TCP Cork */
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

    /* RTCP: version, padding, report count; int = 129 ; hex = 0x81 */
    tmp_8 = 0x81;
    send(fd, &tmp_8, 1, 0);

    /* RTCP: packet type - receiver report */
    tmp_8 = RTCP_RR;
    send(fd, &tmp_8, 1, 0);

    /* RTCP: length */
    tmp_16 = 0x07;
    send(fd, &tmp_16, 2, 0);

    /* RTCP: sender SSRC */
    tmp_32 = RTCP_SSRC;
    send(fd, &tmp_32, 4, 0);

    /* RTCP: Source 1: Identifier */
    send(fd, &identifier, 4, 0);

    /* RTCP: SSRC Contents: Fraction lost */
    tmp_8 = 0x0;
    send(fd, &tmp_8, 1, 0);

    /* RTCP: SSRC Contents: Cumulative packet losts */
    tmp_8 = 0x0;
    send(fd, &tmp_8, 1, 0);
    tmp_16 = 0x0;
    send(fd, &tmp_16, 2, 0);

    /* RTCP: SSRC Contents: Extended highest sequence */
    tmp_16 = rtp_count;
    send(fd, &tmp_16, 2, 0);
    tmp_16 = rtp_highest_seq;
    send(fd, &tmp_16, 2, 0);

    /* RTCP: SSRC Contents: interarrival jitter */
    tmp_32 = 0x113; /* int = 275, taken from wireshark */
    send(fd, &tmp_32, 4, 0);

    /* RTCP: SSRC Contents: Last SR timestamp */
    tmp_32 = rtcp_last_sr_ts;
    send(fd, &tmp_32, 4, 0);

    /* RTCP: SSRC Contents: Timestamp delay */
    if (rtcp_last_sr_ts == 0) {
        tmp_32 = 0x0;
    }
    else {
        tmp_32 = time(NULL) - rtcp_last_sr_ts;
    }
    send(fd, &tmp_32, 4, 0);

    state = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

    return 0;
}
