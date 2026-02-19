#ifndef __MAGIFTPD_H
#define __MAGIFTPD_H

struct ftpclient {
    int fd;
    int data_socket;
    char current_path[PATH_MAX];
    char data_ip[INET6_ADDRSTRLEN];
    int data_port;
    int type;
    char ip[INET6_ADDRSTRLEN];
    char hostip[INET6_ADDRSTRLEN];
    char name[16];
    char password[32];
    int data_srv_socket;
    int status;
    int seclevel;
    int ipver;
};

struct ftpserver {
    int port;
    char *fileroot;
    char *userdb;
    char *upload_folder;
    int upload_seclevel;
    int min_passive_port;
    int max_passive_port;
    int last_passive_port;
    int ipv6;
};

#endif
