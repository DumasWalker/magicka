#include <stdarg.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef __HAIKU__
#define NO_TYPEDEF_BOOL 1
#endif

#include "magimail.h"
#include "broadcast.h"

void broadcast(char *mess, ...) {
	char json[1024];
	char buffer[512];
    struct sockaddr_in s;
	int bcast_sock;
	int broadcastEnable=1;
	int ret;	
	
	
	
	if (config.broadcastPort> 1024 && config.broadcastPort < 65536 && strlen(config.broadcastAddr) > 0) {
		bcast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		ret=setsockopt(bcast_sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
		
		if (ret) {
			close(bcast_sock);
			return;
		}
		memset(&s, 0, sizeof(struct sockaddr_in));
		
		s.sin_family=AF_INET;
		s.sin_addr.s_addr = inet_addr(config.broadcastAddr);
		s.sin_port = htons((unsigned short)config.broadcastPort);
		bind(bcast_sock, (struct sockaddr *)&s, sizeof(struct sockaddr_in));
		
		va_list ap;
		va_start(ap, mess);
		vsnprintf(buffer, 512, mess, ap);
		va_end(ap);		
		
		snprintf(json, 1024, "{\"System\": \"%s\", \"Program\": \"MagiMail\", \"Message\": \"%s\"}", config.cfg_bbsname, buffer);

		ret = sendto(bcast_sock, json, strlen(json) + 1, 0, (struct sockaddr *)&s, sizeof(struct sockaddr_in));
		
		close(bcast_sock);
	}
}
