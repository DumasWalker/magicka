#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#if defined(__OpenBSD__) || defined(__HAIKU__)
#  include <sys/select.h>
#endif

int main(int argc, char **argv) {
    int port;
    int node;
    char *script;
    pid_t pid;
    int server_socket;
	int on = 1;
    struct sockaddr_in server, client;
    int client_fd;
    int c;
    fd_set master, read_fds;
    int len;
    char inbuf[256];
    int i;
    char *arguments[4];
    char last_char = 255;
    struct termios tio_raw;
    struct termios tio_default;
    if (argc < 4) {
        fprintf(stderr, "Usage ./dosbox_shim [port] [node] [script]\n");
        exit(-1);
    }

    port = atoi(argv[1]);
    node = atoi(argv[2]);
    script = strdup(argv[3]);

    if (isatty(STDIN_FILENO))  {
	    tcgetattr(STDIN_FILENO,&tio_default);
	    tio_raw = tio_default;
#ifdef __sun
	    tio_raw.c_iflag &= ~(IMAXBEL|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	    tio_raw.c_oflag &= ~OPOST;
	    tio_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	    tio_raw.c_cflag &= ~(CSIZE|PARENB);
	    tio_raw.c_cflag |= CS8;
	    tio_raw.c_cc[VMIN] = 1;
        tio_raw.c_cc[VTIME] = 0;
#else
	    cfmakeraw(&tio_raw);
#endif
	    tcsetattr(STDIN_FILENO,TCSANOW,&tio_raw);
	    setvbuf(stdout, NULL, _IONBF, 0);
    } else {
	    setvbuf(stdout, NULL, _IONBF, 0);
    }


    pid = fork();

    if (pid < 0) {
        fprintf(stderr, "Error forking!\n");
        exit(-1);
    } else if (pid == 0) {
        arguments[0] = strdup(script);
        sprintf(inbuf, "%d", port);
        arguments[1] = strdup(inbuf);
        sprintf(inbuf, "%d", node);
        arguments[2] = strdup(inbuf);
        arguments[3] = NULL;


        execvp(script, arguments);
    } else {
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1) {
            fprintf(stderr, "Couldn't create socket.\n");
            exit(-1);
        }
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
	        fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
	        exit(1);
	    }
	    server.sin_family = AF_INET;
	    server.sin_addr.s_addr = INADDR_ANY;
	    server.sin_port = htons(port);

        c = sizeof(struct sockaddr_in);

     	if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
		    perror("Bind Failed, Error\n");
		    exit(-1);
	    }

        listen(server_socket, 1);

        client_fd = accept(server_socket, (struct sockaddr *)&client, (socklen_t *)&c);

        if (client_fd == -1) {
            perror("accept");
            exit(-1);
        }

        FD_ZERO(&master);

        FD_SET(STDIN_FILENO, &master);
        FD_SET(client_fd, &master);

        while(1) {
            read_fds = master;

            if (select(client_fd + 1, &read_fds, NULL, NULL, NULL) == -1) {
                perror("select");
                exit(-1);
            }

            if (FD_ISSET(STDIN_FILENO, &read_fds)) {
                len = read(STDIN_FILENO, inbuf, 256);
                for (i=0;i<len;i++) {
                    if (last_char == '\r' && inbuf[i] == '\n') {
                        continue;
                    }

                    last_char = inbuf[i];

                    send(client_fd, &inbuf[i], 1, 0);
                }
            }

            if (FD_ISSET(client_fd, &read_fds)) {
		        do {
	                len = recv(client_fd, inbuf, 256, 0);
	                if (len == 0) {
	                    close(client_fd);
                        if(isatty(STDIN_FILENO))
		                    tcsetattr(STDIN_FILENO,TCSANOW,&tio_default);
       		             exit(0);
               		 }
	                for (i=0;i<len;i++) {
       		        	write(STDOUT_FILENO, &inbuf[i], 1);
			        }
                } while (len == 256);
            }
        }
    }
}
