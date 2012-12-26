/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* headers required by common glibc calls */
#include <sys/types.h>
#include <dirent.h>

/* Duda headers and definition */
#include "webservice.h"
#include "channels.h"
#include "html.h"

DUDA_REGISTER("Duda HTTP Service", "H264 Streamer");

void cb_main(duda_request_t *dr)
{
    response->http_status(dr, 200);
    response->printf(dr, "Hello World!");
    response->end(dr, NULL);
}

/* List channels available */
void cb_list(duda_request_t *dr)
{
    /*
     * Channels are registered into the filesystem under
     * the '/tmp' directory, format is the following:
     *
     * - Each channel must have two files:
     *   - Metadata file (stream header SPS PSP): channel_name.h264st.meta
     *   - Unix socket file: channel_name.h264st.sock
     */

    unsigned int offset;
    DIR *dir;
    struct dirent *ent;

    dir = opendir(CH_ROOT);
    if (!dir) {
        response->http_status(dr, 404);
        response->end(dr, NULL);
    }

    response->printf(dr, HTML_CHANNEL_HEADER);

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }

        /* Look just for regular files and socket */
        if (ent->d_type != DT_REG && ent->d_type != DT_SOCK) {
            continue;
        }

        if (strlen(ent->d_name) <= sizeof(CH_SOCK)) {
            continue;
        }

        offset = (unsigned int) (strlen(ent->d_name) - sizeof(CH_SOCK) + 1);
        if (strncmp(ent->d_name + offset, CH_SOCK, sizeof(CH_SOCK)) != 0) {
            continue;
        }

        response->printf(dr, "Channel: %s<br>\n", ent->d_name);
    }

    closedir(dir);

    response->printf(dr, HTML_CHANNEL_FOOTER);
    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/html");
    response->end(dr, NULL);
}

/* Connect to a streaming */
void cb_play(duda_request_t *dr)
{
    int s;
    char *channel;
    char *file_sock;
    char *file_meta;

    const char *base_url = "/h264streamer/play/";

    /*
     * Get channel name
     *
     */
    s = (dr->sr->uri.len - strlen(base_url));

    if (s < 1) {
        response->http_status(dr, 404);
        response->end(dr, NULL);
    }

    channel = monkey->mem_alloc(s + 1);
    strncpy(channel, dr->sr->uri.data + strlen(base_url), s);
    channel[s] = '\0';

    printf("channel = '%s'\n", channel);

    /* file paths */
    s = strlen(CH_ROOT) + strlen(CH_SOCK) + strlen(channel) + 1;
    file_sock = malloc(s);
    snprintf(file_sock, s, "%s%s%s", CH_ROOT, channel, CH_SOCK);

    printf("file sock: '%s'\n", file_sock);

    file_meta = malloc(s);
    snprintf(file_meta, s, "%s%s%s", CH_ROOT, channel, CH_META);

    printf("file meta: '%s'\n", file_meta);

    /* Fixme, duda is sending the content length header anyways */
    dr->sr->headers.content_length = -1;

    /* send H264 content type header */
    response->http_header(dr, HTTP_CONTENT_TYPE_H264);

    /* set HTTP chunked transfer encoding */
    response->http_header(dr, HTTP_CHUNKED_TE);

    response->http_status(dr, 200);
    response->end(dr, NULL);
}

int duda_main()
{
    map->static_add("/channels", "cb_list");
    map->static_add("/play", "cb_play");

    return 0;
}
