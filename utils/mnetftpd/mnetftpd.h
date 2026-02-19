#ifndef __MAGIFTPD_H
#define __MAGIFTPD_H

struct user_t {
    char *username;
    char *password;
    char *indir;
    char *outdir;
};

struct ftpclient {
    int fd;
    int data_socket;
    char *current_path;
    char data_ip[INET6_ADDRSTRLEN];
    int data_port;
    int type;
    char ip[INET6_ADDRSTRLEN];
    char hostip[INET6_ADDRSTRLEN];
    int data_srv_socket;
    int status;
    int ipver;
    int authenticated;
    struct user_t *user;
};

struct ftpserver {
    int port;
    int min_passive_port;
    int max_passive_port;
    int last_passive_port;
    int ipv6;
};

#endif
