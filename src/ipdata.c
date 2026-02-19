#include <arpa/inet.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <string.h>
#include "bbs.h"
#include "../deps/libIP2Location/IP2Location.h"

extern struct bbs_config conf;
extern char *ipaddress;

void free_ip_data(struct ipdata_t *data) {
	free(data->countrycode);
	free(data->country);
	free(data->city);
	free(data->region);
	free(data);
}

struct ipdata_t *get_ip_data() {
	char buffer[256];
	struct ipdata_t *ipdata;
	IP2Location *ip2loc;
	IP2LocationRecord *ip2rec;

	ip2loc = IP2Location_open(conf.ipdata_location);

	if (!ip2loc) {
		return NULL;
	}

	ip2rec = IP2Location_get_all(ip2loc, ipaddress);

	ipdata = malloz(sizeof(struct ipdata_t));

	ipdata->countrycode = strdup(ip2rec->country_short);
	ipdata->country = strdup(ip2rec->country_long);
	ipdata->region = strdup(ip2rec->region);
	ipdata->city = strdup(ip2rec->city);

	IP2Location_free_record(ip2rec);
	IP2Location_close(ip2loc);

	return ipdata;
}
