/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef NETWORK_H
#define NETWORK_H

int net_tcp_connect(char *host, unsigned long port);
int net_udp_connect(char *host, unsigned long port);
int net_unix_sock(const char *path);
int net_sock_nonblock(int sockfd);

#endif
