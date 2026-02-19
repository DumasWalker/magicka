#if defined(ENABLE_WWW)

#include <microhttpd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <b64/cdecode.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libgen.h>
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
#include <netinet/in.h>
#endif
#include "bbs.h"

#define GET 1
#define POST 2

#define POSTBUFFERSIZE 65536

extern struct bbs_config conf;
extern char *ipaddress;

struct mime_type {
	char *ext;
	char *mime;
};

static struct mime_type **mime_types;
static int mime_types_count;

struct connection_info_s {
	int connection_type;
	struct user_record *user;
	char *url;
	struct ptr_vector keys;
	struct ptr_vector values;
	int count;
	struct MHD_PostProcessor *pp;
};

void *www_logger(void *cls, const char *uri, struct MHD_Connection *con) {
	struct sockaddr *so = (struct sockaddr *)MHD_get_connection_info(con, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
	char *ipaddr;
	if (so->sa_family == AF_INET) {
		ipaddr = (char *)malloz(INET_ADDRSTRLEN + 1);
		inet_ntop(AF_INET, &((struct sockaddr_in *)so)->sin_addr, ipaddr, INET_ADDRSTRLEN);
	} else if (so->sa_family == AF_INET6) {
		ipaddr = (char *)malloz(INET6_ADDRSTRLEN + 1);
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)so)->sin6_addr, ipaddr, INET6_ADDRSTRLEN);
	}
	dolog_www(ipaddr, "%s", uri);
	free(ipaddr);

	return NULL;
}

char *www_get_my_url(struct MHD_Connection *con) {
	if (MHD_get_connection_info(con, MHD_CONNECTION_INFO_PROTOCOL) != NULL) {
		return conf.ssl_url;
	} else {
		return conf.www_url;
	}
}

/* void www_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
	struct connection_info_s *con_info = *con_cls;
	int i;
	if (con_info == NULL) {
		return;
	}

	if (con_info->connection_type == POST) {

		if (con_info->count > 0) {
			ptr_vector_apply(&con_info->values, free);
			ptr_vector_apply(&con_info->keys, free);
			destroy_ptr_vector(&con_info->values);
			destroy_ptr_vector(&con_info->keys);
		}

		if (con_info->pp != NULL) {
			MHD_destroy_post_processor(con_info->pp);
		}
	}
	if (con_info->user != NULL) {
		free(con_info->user->loginname);
		free(con_info->user->password);
		free(con_info->user->firstname);
		free(con_info->user->lastname);
		free(con_info->user->email);
		free(con_info->user->location);
		free(con_info->user->sec_info);
		free(con_info->user->signature);
		free(con_info->user);
	}

	free(con_info->url);
	free(con_info);
} */

void www_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
    struct connection_info_s *con_info = (struct connection_info_s *)*con_cls;
    
    if (con_info == NULL) return;

    // 1. Post Processor
    if (con_info->connection_type == POST && con_info->pp != NULL) {
        MHD_destroy_post_processor(con_info->pp);
        con_info->pp = NULL;
    }

    // 2. Vector Cleanup (Safety first: apply free ONLY if there is something to free)
    if (con_info->values.len > 0) ptr_vector_apply(&con_info->values, free);
    if (con_info->keys.len > 0)   ptr_vector_apply(&con_info->keys, free);
    
    destroy_ptr_vector(&con_info->values);
    destroy_ptr_vector(&con_info->keys);

    // 3. User Cleanup (Deep safety)
    if (con_info->user != NULL) {
        struct user_record *u = con_info->user;
        if (u->loginname) free(u->loginname);
        if (u->password)  free(u->password);
        if (u->firstname) free(u->firstname);
        if (u->lastname)  free(u->lastname);
        if (u->email)     free(u->email);
        if (u->location)  free(u->location);
        if (u->sec_info)  free(u->sec_info);
        if (u->signature) free(u->signature);
        free(u);
        con_info->user = NULL;
    }

    // 4. Final Structure
    if (con_info->url) {
        free(con_info->url);
        con_info->url = NULL;
    }
    
    free(con_info);
    *con_cls = NULL; // Crucial: Tell libmicrohttpd this is gone
}

/*static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                        const char *key, const char *filename,
                        const char *content_type, const char *transfer_encoding,
                        const char *data, uint64_t off, size_t size) { */
/*static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                        const char *key, const char *filename,
                        const char *content_type, const char *transfer_encoding,
                        const char *data, long long unsigned int off, unsigned int size) { */
/* 1. Change 'int' to 'enum MHD_Result' */
/* 2. Change 'unsigned int size' to 'size_t size' */
static enum MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                                    const char *key, const char *filename,
                                    const char *content_type, const char *transfer_encoding,
                                    const char *data, uint64_t off, size_t size) {
	struct connection_info_s *con_info = coninfo_cls;

	if (size == 0)
		return MHD_NO;
	if (con_info == NULL)
		return MHD_NO;
	if (con_info->connection_type != POST)
		return MHD_NO;
	for (int i = 0; i < con_info->count; i++) {
		if (strcmp(ptr_vector_get(&con_info->keys, i), key) == 0) {
			char *value = ptr_vector_get(&con_info->values, i);
			size_t newsize = strlen(value) + size + 1;
			char *newvalue = realloc(value, newsize);
			strlcat(newvalue, data, newsize);
			ptr_vector_put(&con_info->values, newvalue, i);
			return MHD_YES;
		}
	}

	ptr_vector_append(&con_info->keys, strdup(key));
	ptr_vector_append(&con_info->values, strdup(data));
	con_info->count++;
	return MHD_YES;
}

void www_init() {
	FILE *fptr;
	char buffer[PATH_MAX];
	struct ptr_vector vec = EMPTY_PTR_VECTOR;

	snprintf(buffer, sizeof buffer, "%s/mime.types", conf.www_path);
	fptr = fopen(buffer, "r");
	if (!fptr) {
		return;
	}
	fgets(buffer, sizeof buffer, fptr);
	while (!feof(fptr)) {
		chomp(buffer);

		for (char *p = buffer; *p != '\0'; ++p) {
			if (*p == ' ') {
				*p = '\0';
				struct mime_type *atype = (struct mime_type *)malloz(sizeof(struct mime_type));
				atype->mime = strdup(buffer);
				atype->ext = strdup(p + 1);
				ptr_vector_append(&vec, atype);
				break;
			}
		}

		fgets(buffer, sizeof buffer, fptr);
	}
	fclose(fptr);

	mime_types_count = ptr_vector_len(&vec);
	mime_types = (struct mime_type **)consume_ptr_vector(&vec);
}

char *www_get_mime_type(const char *extension) {
	static char default_mime_type[] = "application/octet-stream";

	if (extension != NULL)
		for (int i = 0; i < mime_types_count; i++)
			if (strcasecmp(extension, mime_types[i]->ext) == 0)
				return mime_types[i]->mime;
	return default_mime_type;
}

int www_401(char *header, char *footer, struct MHD_Connection *connection) {
	char buffer[PATH_MAX];
	char *page, *page_tmp;
	char *whole_page;
	struct MHD_Response *response;
	int ret;
	FILE *fptr;

	snprintf(buffer, PATH_MAX, "%s/401.tpl", conf.www_path);

	page_tmp = file2str(buffer);

	if (page_tmp == NULL) {
		page_tmp = strdup("Missing Content");
		if (page_tmp == NULL) {
			return -1;
		}
	}

	page = str_replace(page_tmp, "@@WWW_URL@@", conf.www_url);
	free(page_tmp);

	whole_page = str3dup(header, page, footer);

	response = MHD_create_response_from_buffer(strlen(whole_page), (void *)whole_page, MHD_RESPMEM_MUST_FREE);

	MHD_add_response_header(response, "WWW-Authenticate", "Basic realm=\"BBS Area\"");

	ret = MHD_queue_response(connection, 401, response);
	MHD_destroy_response(response);
	free(page);

	return 0;
}

int www_404(char *header, char *footer, struct MHD_Connection *connection) {
	char buffer[PATH_MAX];
	char *page, *page_tmp;
	struct stat s;
	char *whole_page;
	struct MHD_Response *response;
	int ret;
	FILE *fptr;

	snprintf(buffer, PATH_MAX, "%s/404.tpl", conf.www_path);

	page_tmp = file2str(buffer);

	if (page_tmp == NULL) {
		page_tmp = (char *)strdup("Missing Content");
		if (page_tmp == NULL) {
			return -1;
		}
	}

	page = str_replace(page_tmp, "@@WWW_URL@@", conf.www_url);
	free(page_tmp);

	whole_page = str3dup(header, page, footer);

	response = MHD_create_response_from_buffer(strlen(whole_page), (void *)whole_page, MHD_RESPMEM_MUST_FREE);

	ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response(response);
	free(page);

	return 0;
}

int www_403(char *header, char *footer, struct MHD_Connection *connection) {
	char buffer[PATH_MAX];
	char *page, *page_tmp;
	struct stat s;
	char *whole_page;
	struct MHD_Response *response;
	int ret;
	FILE *fptr;
	char *endptr;

	snprintf(buffer, PATH_MAX, "%s/403.tpl", conf.www_path);

	page_tmp = file2str(buffer);

	if (page_tmp == NULL) {
		page_tmp = strdup("Missing Content");
		if (page_tmp == NULL) {
			return -1;
		}
	}

	page = str_replace(page_tmp, "@@WWW_URL@@", www_get_my_url(connection));
	free(page_tmp);

	whole_page = str3dup(header, page, footer);

	response = MHD_create_response_from_buffer(strlen(whole_page), (void *)whole_page, MHD_RESPMEM_MUST_FREE);

	ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response(response);
	free(page);

	return 0;
}

struct user_record *www_auth_ok(struct MHD_Connection *connection, const char *url) {
	const char *ptr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
	char *user_password;
	base64_decodestate state;
	char decoded_pass[34];
	int len;
	char *username;
	char *password;
	int i;
	struct user_record *u;

	if (ptr == NULL) {
		return NULL;
	}

	user_password = strdup(ptr);

	if (strncasecmp(user_password, "basic ", 6) == 0) {
		if (strlen(&user_password[6]) <= 48) {
			base64_init_decodestate(&state);
			len = base64_decode_block(&user_password[6], strlen(&user_password[6]), decoded_pass, &state);
			decoded_pass[len] = '\0';

			username = decoded_pass;
			for (i = 0; i < strlen(decoded_pass); i++) {
				if (decoded_pass[i] == ':') {
					decoded_pass[i] = '\0';
					password = &decoded_pass[i + 1];
					break;
				}
			}
			u = check_user_pass(username, password);
			free(user_password);

			return u;
		}
	}
	free(user_password);
	return NULL;
}

/*int www_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {*/
/*enum MHD_Result www_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {*/
enum MHD_Result www_handler(void *cls,
                            struct MHD_Connection *connection,
                            const char *url,
                            const char *method,
                            const char *version,
                            const char *upload_data,
                            size_t *upload_data_size, 
                            void **con_cls) { 

	struct MHD_Response *response;

	enum MHD_Result ret;
	char *page, *page_tmp;
	char buffer[PATH_MAX];
	struct stat s;
	char *header, *header_tmp;
	char *footer, *footer_tmp;
	char *whole_page;
	FILE *fptr;
	char *mime;
	int i;
	int fno;
	const char *url_ = url;
	char *subj, *to, *body;
	struct connection_info_s *con_inf;
	int conference, area, msg;
	char *url_copy;
	char *aptr;
	const char *val;
	int skip;
	int replyid;
	char *filename;
	int email;
	char *endptr;
	int file_dir;
	int file_sub;
	char *filen;
	char *content_type = NULL;
	page = NULL;


	if (strcmp(method, "GET") == 0) {
		if (*con_cls == NULL) {
			con_inf = (struct connection_info_s *)malloz(sizeof(struct connection_info_s));
			if (!con_inf) {
				return MHD_NO;
			}
			con_inf->connection_type = GET;
			con_inf->user = NULL;
			con_inf->count = 0;
			con_inf->url = strdup(url);
			con_inf->pp = NULL;
			init_ptr_vector(&con_inf->values);
			init_ptr_vector(&con_inf->keys);
			*con_cls = con_inf;
			return MHD_YES;
		}
	} else if (strcmp(method, "POST") == 0) {
		if (*con_cls == NULL) {
			con_inf = (struct connection_info_s *)malloz(sizeof(struct connection_info_s));
			if (!con_inf) {
				return MHD_NO;
			}
			con_inf->connection_type = POST;
			con_inf->user = NULL;
			con_inf->count = 0;
			con_inf->url = strdup(url);
			con_inf->pp = NULL;
			init_ptr_vector(&con_inf->values);
			init_ptr_vector(&con_inf->keys);
			*con_cls = con_inf;
			return MHD_YES;
		}
	} else {
		return MHD_NO;
	}

	if (MHD_get_connection_info(connection, MHD_CONNECTION_INFO_PROTOCOL) == NULL) {
		if (conf.www_redirect_ssl && conf.ssl_url != NULL) {
			char *ssl_url = malloz(strlen(conf.ssl_url) + strlen(url_) + 1);
			if (!ssl_url) {
				return MHD_NO;
			}


			response = MHD_create_response_from_buffer(2, "ok", MHD_RESPMEM_PERSISTENT);

			if (conf.ssl_url[strlen(conf.ssl_url) -1] == '/') {
				sprintf(ssl_url, "%s%s", conf.ssl_url, &url_[1]);
			} else {
				sprintf(ssl_url, "%s%s", conf.ssl_url, url_);
			}
			MHD_add_response_header (response, "Location", ssl_url);
			free(ssl_url);
			ret = MHD_queue_response (connection, MHD_HTTP_FOUND, response);
			MHD_destroy_response(response);
			return ret;
		}
	}

	con_inf = *con_cls;

	snprintf(buffer, PATH_MAX, "%s/header.tpl", conf.www_path);

	header_tmp = file2str(buffer);

	if (header_tmp == NULL) {
		header_tmp = str5dup("<HTML>\n<HEAD>\n<TITLE>", conf.bbs_name, "</TITLE>\n</HEAD>\n<BODY>\n<H1>", conf.bbs_name, "</H1><HR />");
		if (header_tmp == NULL) {
			return MHD_NO;
		}
	}

	header = str_replace(header_tmp, "@@WWW_URL@@", www_get_my_url(connection));
	free(header_tmp);

	snprintf(buffer, PATH_MAX, "%s/footer.tpl", conf.www_path);

	footer_tmp = file2str(buffer);

	if (footer_tmp == NULL) {
		footer_tmp = strdup("<HR />Powered by Magicka BBS</BODY></HTML>");
		if (footer_tmp == NULL) {
			free(header);
			return MHD_NO;
		}
	}

	footer = str_replace(footer_tmp, "@@WWW_URL@@", www_get_my_url(connection));
	free(footer_tmp);

	if (strcmp(method, "GET") == 0) {
		if (strcasecmp(url, "/") == 0) {

			snprintf(buffer, PATH_MAX, "%s/index.tpl", conf.www_path);

			page_tmp = file2str(buffer);

			if (page_tmp == NULL) {
				page_tmp = strdup("Missing Content");
				if (page_tmp == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			}

			page = str_replace(page_tmp, "@@WWW_URL@@", www_get_my_url(connection));
			free(page_tmp);

			whole_page = str3dup(header, page, footer);
		} else if (strcasecmp(url, "/last10/") == 0 || strcasecmp(url, "/last10") == 0) {
			page = www_last10(connection);
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/scripts/", 9) == 0) {
			page = www_script_parse(connection, &url[9]);
			if (page == NULL) {
				www_404(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			whole_page = str3dup(header, page, footer);			
		} else if (strcasecmp(url, "/blog") == 0 || strcasecmp(url, "/blog/") == 0) {
			page = www_blog(connection);
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strcasecmp(url, "/blog/rss") == 0 || strcasecmp(url, "/blog/rss/") == 0) {
			content_type = strdup("text/xml");
			page = www_blog_rss(connection);
			whole_page = str2dup("<?xml version=\"1.0\"?>\n", page);
		} else if (strcasecmp(url, "/email/") == 0 || strcasecmp(url, "/email") == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			page = www_email_summary(connection, con_inf->user);
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strcasecmp(url, "/email/new") == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			page = www_new_email(connection);
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/email/delete/", 14) == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			email = strtol(&url[14], &endptr, 10);
			if (endptr == &url[14] || !www_email_delete(connection, con_inf->user, email)) {
				page = strdup("<h1>Error Deleting Email.</h1>");
				if (page == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			} else {
				page = strdup("<h1>Email Deleted!</h1>");
				if (page == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			}
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/email/", 7) == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			email = strtol(&url[7], &endptr, 10);
			if (endptr == &url[7]) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			page = www_email_display(connection, con_inf->user, email);
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strcasecmp(url, "/msgs/") == 0 || strcasecmp(url, "/msgs") == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			page = www_msgs_arealist(connection, con_inf->user);
			if (page == NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/msgs/flag/", 11) == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			conference = -1;
			area = -1;
			msg = -1;
			url_copy = strdup(&url[11]);

			aptr = strtok(url_copy, "/");
			if (aptr != NULL) {
				conference = strtol(aptr, &endptr, 10);
				if (endptr == aptr) {
					conference = -1;
				}
				aptr = strtok(NULL, "/");
				if (aptr != NULL) {
					area = strtol(aptr, &endptr, 10);
					if (endptr == aptr) {
						area = -1;
					}
					aptr = strtok(NULL, "/");
					if (aptr != NULL) {
						msg = strtol(aptr, &endptr, 10);
						if (endptr == aptr) {
							msg = -1;
						}
					}
				}
			}
			free(url_copy);

			if (conference != -1 && area != -1 && msg != -1) {
				msgbase_flag_unflag(con_inf->user, conference, area, msg);
				response = MHD_create_response_from_buffer(0, (void *)"", MHD_RESPMEM_PERSISTENT);
				snprintf(buffer, PATH_MAX, "%smsgs/%d/%d/%d", www_get_my_url(connection), conference, area, msg);

				MHD_add_response_header(response, "Location", buffer);
				MHD_queue_response(connection, MHD_HTTP_FOUND, response);
				MHD_destroy_response(response);
				free(header);
				free(footer);
				return MHD_YES;
			}
			www_404(header, footer, connection);
			free(header);
			free(footer);
			return MHD_YES;
		} else if (strncasecmp(url, "/msgs/new/", 10) == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			conference = -1;
			area = -1;
			url_copy = strdup(&url[10]);

			aptr = strtok(url_copy, "/");
			if (aptr != NULL) {
				conference = strtol(aptr, &endptr, 10);
				if (endptr == aptr) {
					conference = -1;
				}
				aptr = strtok(NULL, "/");
				if (aptr != NULL) {
					area = strtol(aptr, &endptr, 10);
					if (endptr == aptr) {
						area = -1;
					}
				}
			}
			free(url_copy);

			if (area != -1 && conference != -1) {
				page = www_new_msg(connection, con_inf->user, conference, area);
			} else {
				free(header);
				free(footer);
				return MHD_NO;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/msgs/", 6) == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			conference = -1;
			area = -1;
			msg = -1;
			url_copy = strdup(&url[6]);

			aptr = strtok(url_copy, "/");
			if (aptr != NULL) {
				conference = strtol(aptr, &endptr, 10);
				if (endptr == aptr) {
					conference = -1;
				}
				aptr = strtok(NULL, "/");
				if (aptr != NULL) {
					area = strtol(aptr, &endptr, 10);
					if (endptr == aptr) {
						area = -1;
					}
					aptr = strtok(NULL, "/");
					if (aptr != NULL) {
						msg = strtol(aptr, &endptr, 10);
						if (endptr == aptr) {
							msg = -1;
						}
					}
				}
			}
			free(url_copy);

			val = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "skip");

			if (val != NULL) {
				skip = atoi(val);
			} else {
				skip = 0;
			}

			if (conference != -1 && area != -1 && msg == -1) {
				page = www_msgs_messagelist(connection, con_inf->user, conference, area, skip);
			} else if (conference != -1 && area != -1 && msg != -1) {
				page = www_msgs_messageview(connection, con_inf->user, conference, area, msg);
			}

			if (page == NULL) {
				if (www_403(header, footer, connection) != 0) {
					free(header);
					free(footer);
					return MHD_NO;
				}
				free(header);
				free(footer);
				return MHD_YES;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/static/", 8) == 0) {
			// sanatize path
			if (strstr(url, "/..") != NULL) {
				free(header);
				free(footer);
				return MHD_NO;
			}

			mime = NULL;
			// get mimetype
			for (i = strlen(url); i > 0; --i) {
				if (url[i] == '.') {
					mime = www_get_mime_type(&url[i + 1]);
					break;
				}
				if (url[i] == '/') {
					mime = www_get_mime_type(NULL);
					break;
				}
			}

			if (mime = NULL) {
				mime = www_get_mime_type(NULL);
			}

			// load file

			snprintf(buffer, sizeof buffer, "%s%s", conf.www_path, url);
			if (stat(buffer, &s) == 0 && S_ISREG(s.st_mode)) {
				fno = open(buffer, O_RDONLY);
				if (fno != -1) {
					//static_buffer = (char *)malloz(s.st_size + 1);
					//read(fno, static_buffer, s.st_size);
					response = MHD_create_response_from_fd(s.st_size, fno);
					//response = MHD_create_response_from_buffer (s.st_size, (void*) static_buffer, MHD_RESPMEM_MUST_FREE);
					MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mime);
					ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
					MHD_destroy_response(response);
					free(header);
					free(footer);
					return ret;
				} else {
					if (www_403(header, footer, connection) != 0) {
						free(header);
						free(footer);
						return MHD_NO;
					}
					free(header);
					free(footer);
					return MHD_YES;
				}
			} else {
				if (www_404(header, footer, connection) != 0) {
					free(header);
					free(footer);
					return MHD_NO;
				}
				free(header);
				free(footer);
				return MHD_YES;
			}
		} else if (strcasecmp(url, "/files/areas/") == 0 || strcasecmp(url, "/files/areas") == 0) {
			page = www_files_areas(connection);
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/files/areas/", 13) == 0) {
			file_dir = -1;
			file_sub = -1;
			filen = NULL;
			url_copy = strdup(&url[13]);

			aptr = strtok(url_copy, "/");
			if (aptr != NULL) {
				file_dir = strtol(aptr, &endptr, 10);
				if (endptr == aptr) {
					file_dir = -1;
				}
				aptr = strtok(NULL, "/");
				if (aptr != NULL) {
					file_sub = strtol(aptr, &endptr, 10);
					if (endptr == aptr) {
						file_sub = -1;
					}
					aptr = strtok(NULL, "/");
					if (aptr != NULL) {
						filen = strdup(aptr);
					}
				}
			}
			free(url_copy);

			if (file_dir != -1 && file_sub != -1 && filen == NULL) {
				if (file_dir >= 0 && file_dir < ptr_vector_len(&conf.file_directories)) {
					struct file_directory *dir = ptr_vector_get(&conf.file_directories, file_dir);
					assert(dir != NULL);
					if (file_sub >= 0 && file_sub < ptr_vector_len(&dir->file_subs)) {
						struct file_sub *sub = ptr_vector_get(&dir->file_subs, file_sub);
						assert (sub != NULL);
						if (sub->display_on_web == 2) {
							con_inf->user = www_auth_ok(connection, url_);
							if (con_inf->user == NULL) {
								www_401(header, footer, connection);
								free(header);
								free(footer);
								return MHD_YES;
							}
						}
						if (sub->display_on_web != 0) {
							page = www_files_display_listing(connection, file_dir, file_sub);
						}
					}
				}
			} else if (file_dir != -1 && file_sub != -1 && filen != NULL) {
				if (file_dir >= 0 && file_dir < ptr_vector_len(&conf.file_directories)) {
					struct file_directory *dir = ptr_vector_get(&conf.file_directories, file_dir);
					if (dir->display_on_web == 2) {
						con_inf->user = www_auth_ok(connection, url_);
						if (con_inf->user == NULL) {
							www_401(header, footer, connection);
							free(header);
							free(footer);
							return MHD_YES;
						}
					}
					if (file_sub >= 0 && file_sub < ptr_vector_len(&dir->file_subs)) {
						struct file_sub *sub = ptr_vector_get(&dir->file_subs, file_sub);
						assert(sub != NULL);

						if (sub->display_on_web != 0) {
							// send file
							filename = www_files_get_from_area(file_dir, file_sub, filen);
							free(filen);
							if (filename != NULL) {
								mime = NULL;
								// get mimetype
								for (i = strlen(filename); i > 0; --i) {
									if (filename[i] == '.') {
										mime = www_get_mime_type(&filename[i + 1]);
										break;
									}
									if (filename[i] == '/') {
										mime = www_get_mime_type(NULL);
										break;
									}
								}

								if (mime = NULL) {
									mime = www_get_mime_type(NULL);
								}
								if (stat(filename, &s) == 0 && S_ISREG(s.st_mode)) {
									fno = open(filename, O_RDONLY);
									if (fno != -1) {

										response = MHD_create_response_from_fd(s.st_size, fno);
										MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mime);
										snprintf(buffer, sizeof buffer, "%ld", s.st_size);
										MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_LENGTH, buffer);

										snprintf(buffer, PATH_MAX, "attachment; filename=\"%s\"", basename(filename));
										MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_DISPOSITION, buffer);
										ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
										MHD_destroy_response(response);
										free(header);
										free(footer);
										free(filename);
										return ret;
									}
								}
								free(filename);
							}
							if (www_404(header, footer, connection) != 0) {
								free(header);
								free(footer);
								return MHD_NO;
							}
							free(header);
							free(footer);
							return MHD_YES;
						}
					} else {
						free(filen);
					}
				} else {
					free(filen);
				}

			}
			if (page == NULL) {
				if (www_403(header, footer, connection) != 0) {
					free(header);
					free(footer);
					return MHD_NO;
				}
				free(header);
				free(footer);
				return MHD_YES;
			}
			whole_page = str3dup(header, page, footer);
		} else if (strncasecmp(url, "/files/", 7) == 0) {
			filename = www_decode_hash(&url[7]);
			if (filename != NULL) {
				mime = NULL;
				// get mimetype
				for (i = strlen(filename); i > 0; --i) {
					if (filename[i] == '.') {
						mime = www_get_mime_type(&filename[i + 1]);
						break;
					}
					if (filename[i] == '/') {
						mime = www_get_mime_type(NULL);
						break;
					}
				}

				if (mime = NULL) {
					mime = www_get_mime_type(NULL);
				}

				if (stat(filename, &s) == 0 && S_ISREG(s.st_mode)) {
					fno = open(filename, O_RDONLY);
					if (fno != -1) {

						response = MHD_create_response_from_fd(s.st_size, fno);
						MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mime);
						snprintf(buffer, sizeof buffer, "%ld", s.st_size);
						MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_LENGTH, buffer);

						snprintf(buffer, PATH_MAX, "attachment; filename=\"%s\"", basename(filename));
						MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_DISPOSITION, buffer);
						ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
						MHD_destroy_response(response);
						free(header);
						free(footer);
						free(filename);
						return ret;
					}
				}
				free(filename);
			}
			if (www_404(header, footer, connection) != 0) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			free(header);
			free(footer);
			return MHD_YES;
		} else {
			if (www_404(header, footer, connection) != 0) {
				free(header);
				free(footer);
				return MHD_NO;
			}
			free(header);
			free(footer);
			return MHD_YES;
		}
	} else if (strcmp(method, "POST") == 0) {
		if (strcasecmp(url, "/email/") == 0 || strcasecmp(url, "/email") == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			if (con_inf->pp == NULL) {
				con_inf->pp = MHD_create_post_processor(connection, POSTBUFFERSIZE, iterate_post, (void *)con_inf);
			}
			if (*upload_data_size != 0) {

				MHD_post_process(con_inf->pp, upload_data, *upload_data_size);
				*upload_data_size = 0;

				return MHD_YES;
			}
			subj = NULL;
			to = NULL;
			body = NULL;
			for (i = 0; i < con_inf->count; i++) {
				const char *key = ptr_vector_get(&con_inf->keys, i);
				char *value = ptr_vector_get(&con_inf->values, i);
				if (strcmp(key, "recipient") == 0) {
					to = value;
				} else if (strcmp(key, "subject") == 0) {
					subj = value;
				} else if (strcmp(key, "body") == 0) {
					body = value;
				}
			}
			if (!www_send_email(con_inf->user, to, subj, body)) {
				page = strdup("<h1>Error Sending Email (Check User Exists?)</h1>");
				if (page == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			} else {
				page = strdup("<h1>Email Sent!</h1>");
				if (page == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			}
			whole_page = str3dup(header, page, footer);
		} else if (strcasecmp(url, "/msgs/") == 0 || strcasecmp(url, "/msgs") == 0) {
			con_inf->user = www_auth_ok(connection, url_);

			if (con_inf->user == NULL) {
				www_401(header, footer, connection);
				free(header);
				free(footer);
				return MHD_YES;
			}
			if (con_inf->pp == NULL) {
				con_inf->pp = MHD_create_post_processor(connection, POSTBUFFERSIZE, iterate_post, (void *)con_inf);
			}

			if (*upload_data_size != 0) {
				MHD_post_process(con_inf->pp, upload_data, *upload_data_size);
				*upload_data_size = 0;

				return MHD_YES;
			}
			subj = NULL;
			to = NULL;
			body = NULL;
			replyid = -1;
			conference = -1;
			area = -1;

			for (i = 0; i < con_inf->count; i++) {
				const char *key = ptr_vector_get(&con_inf->keys, i);
				char *value = ptr_vector_get(&con_inf->values, i);
				if (strcmp(key, "recipient") == 0) {
					to = value;
				} else if (strcmp(key, "subject") == 0) {
					subj = value;
				} else if (strcmp(key, "body") == 0) {
					body = value;
				} else if (strcmp(key, "conference") == 0) {
					conference = strtol(value, &endptr, 10);
					if (endptr == value) {
						conference = -1;
					}
				} else if (strcmp(key, "area") == 0) {
					area = strtol(value, &endptr, 10);
					if (endptr == value) {
						area = -1;
					}
				} else if (strcmp(key, "replyid") == 0) {
					replyid = strtol(value, &endptr, 10);
					if (endptr == value) {
						replyid = -1;
					}
				}
			}

			if (!www_send_msg(con_inf->user, to, subj, conference, area, replyid, body)) {
				page = strdup("<h1>Error Sending Message</h1>");
				if (page == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			} else {
				page = www_sent_msg_page(connection, conference, area);
				if (page == NULL) {
					free(header);
					free(footer);
					return MHD_NO;
				}
			}
			whole_page = str3dup(header, page, footer);
		} else {
			free(header);
			free(footer);
			return MHD_NO;
		}
	} else {
		free(header);
		free(footer);
		return MHD_NO;
	}
	response = MHD_create_response_from_buffer(strlen(whole_page), (void *)whole_page, MHD_RESPMEM_MUST_FREE);

	if (content_type == NULL) {
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
	} else {
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, content_type);
		free(content_type);
	}

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	free(page);
	free(header);
	free(footer);

	return ret;
}
#endif
