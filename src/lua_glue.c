#include <sys/utsname.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "bbs.h"
#include "lua/lua.h"
#include "lua/lauxlib.h"
#include "lua/lualib.h"
#include "msglib/msglib.h"
#include "libuuid/uuid.h"

extern int mynode;
extern struct bbs_config conf;
extern char *ipaddress;
extern struct user_record *gUser;

int l_bbsWString(lua_State *L) {
	char *str = (char *)lua_tostring(L, -1);

	s_printf("%s", str);

	return 0;
}

int l_displayBlog(lua_State *L) {
	blog_display();

	return 0;
}

int l_getBlogEntryCount(lua_State *L) {
	lua_pushnumber(L, blog_get_entry_count());
	return 1;
}

int l_getBlogEntry(lua_State *L) {
	int entryno = lua_tonumber(L, -1);
	char *entry = blog_get_entry(entryno);
	lua_pushstring(L, entry);
	free(entry);
	return 1;
}

int l_getBlogAuthor(lua_State *L) {
	int entryno = lua_tonumber(L, -1);
	char *entry = blog_get_author(entryno);
	lua_pushstring(L, entry);
	free(entry);
	return 1;
}

int l_getBlogTitle(lua_State *L) {
	int entryno = lua_tonumber(L, -1);
	char *entry = blog_get_title(entryno);
	lua_pushstring(L, entry);
	free(entry);
	return 1;
}

int l_getBlogDate(lua_State *L) {
	int entryno = lua_tonumber(L, -1);
	time_t entry = blog_get_date(entryno);
	lua_pushnumber(L, entry);
	return 1;
}

int l_bbsRString(lua_State *L) {
	char buffer[256];
	int len = lua_tonumber(L, -1);

	if (len > 256) {
		len = 256;
	}

	s_readstring(buffer, len);

	lua_pushstring(L, buffer);

	return 1;
}

int l_bbsRChar(lua_State *L) {
	char c;

	c = s_getchar();

	lua_pushlstring(L, &c, 1);

	return 1;
}

int l_bbsDisplayAnsiPause(lua_State *L) {
	char *str = (char *)lua_tostring(L, -1);
	char buffer[PATH_MAX];
	struct stat s;
	if (strchr(str, '/') == NULL) {
		if (gUser != NULL) {
			snprintf(buffer, sizeof buffer, "%s/%s.%d.ans", conf.ansi_path, str, gUser->sec_level);
			if (stat(buffer, &s) != 0) {
				snprintf(buffer, sizeof buffer, "%s/%s.ans", conf.ansi_path, str);
			}
		} else {
			snprintf(buffer, sizeof buffer, "%s/%s.ans", conf.ansi_path, str);
		}
		s_displayansi_pause(buffer, 1);
	} else {
		s_displayansi_pause(str, 1);
	}
	return 0;
}

int l_bbsDisplayAnsi(lua_State *L) {
	char *str = (char *)lua_tostring(L, -1);

	s_displayansi(str);

	return 0;
}

int l_bbsVersion(lua_State *L) {
	char buffer[64];
	snprintf(buffer, 64, "Magicka BBS v%d.%d (%s)", VERSION_MAJOR, VERSION_MINOR, VERSION_STR);

	lua_pushstring(L, buffer);

	return 1;
}

int l_bbsNode(lua_State *L) {
	lua_pushnumber(L, mynode);

	return 1;
}

int l_bbsReadLast10(lua_State *L) {
	int offset = lua_tonumber(L, -1);
	struct last10_callers l10;
	FILE *fptr;

	fptr = fopen("last10v2.dat", "rb");
	if (!fptr) {
		return 0;
	}
	fseek(fptr, offset * sizeof(struct last10_callers), SEEK_SET);
	if (fread(&l10, sizeof(struct last10_callers), 1, fptr) == 0) {
		return 0;
	}
	fclose(fptr);

	lua_pushstring(L, l10.name);
	lua_pushstring(L, l10.location);
	lua_pushnumber(L, l10.time);
	lua_pushnumber(L, l10.calls);
	return 4;
}

int l_bbsGetEmailCount(lua_State *L) {
	lua_pushnumber(L, mail_getemailcount(gUser));

	return 1;
}

int l_bbsFullEmailScan(lua_State *L) {
	full_email_scan();
	return 0;
}

int l_bbsFullMailScan(lua_State *L) {
	full_mail_scan(gUser);
	return 0;
}

int l_bbsPersonalMailScan(lua_State *L) {
	full_mail_scan_personal(gUser);
	return 0;
}

int l_bbsMailScan(lua_State *L) {
	mail_scan(gUser);
	return 0;
}

int l_bbsFileScan(lua_State *L) {
	file_scan();
	return 0;
}

int l_bbsRunDoor(lua_State *L) {
	char *cmd = (char *)lua_tostring(L, 1);
	int stdio = lua_toboolean(L, 2);
	char *codepage = (char *)lua_tostring(L, 3);
	rundoor(gUser, cmd, stdio, codepage);

	return 0;
}

int l_ipAddress(lua_State *L) {
	lua_pushstring(L, ipaddress);
	return 1;
}

int l_ipInfo(lua_State *L) {
	struct ipdata_t *data;

	data = get_ip_data();
	if (data == NULL) {
		lua_pushstring(L, "--");
		lua_pushstring(L, "Unknown");
		lua_pushstring(L, "Unknown");
		lua_pushstring(L, "Unknown");
	} else {
		lua_pushstring(L, data->countrycode);
		lua_pushstring(L, data->country);
		lua_pushstring(L, data->region);
		lua_pushstring(L, data->city);
		free_ip_data(data);
	}

	return 4;
}

int l_bbsTimeLeft(lua_State *L) {
	lua_pushnumber(L, gUser->timeleft);

	return 1;
}

int l_bbsDisplayAutoMsg(lua_State *L) {
	automessage_display();
	return 0;
}

int l_getMailAreaInfo(lua_State *L) {
	assert(gUser != NULL);
	lua_pushnumber(L, gUser->cur_mail_conf);
	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, gUser->cur_mail_conf);
	assert(mc != NULL);
	lua_pushstring(L, mc->name);
	lua_pushnumber(L, gUser->cur_mail_area);
	struct mail_area *ma = ptr_vector_get(&mc->mail_areas, gUser->cur_mail_area);
	assert(ma != NULL);
	lua_pushstring(L, ma->name);

	return 4;
}

int l_getFileAreaInfo(lua_State *L) {
	assert(gUser != NULL);
	lua_pushnumber(L, gUser->cur_file_dir);
	struct file_directory *dir = ptr_vector_get(&conf.file_directories, gUser->cur_file_dir);
	assert(dir != NULL);
	lua_pushstring(L, dir->name);
	lua_pushnumber(L, gUser->cur_file_sub);
	struct file_sub *sub = ptr_vector_get(&dir->file_subs, gUser->cur_file_sub);
	assert(sub != NULL);
	lua_pushstring(L, sub->name);

	return 4;
}

int l_getBBSInfo(lua_State *L) {
	struct utsname name;

	uname(&name);

	lua_pushstring(L, conf.bbs_name);
	lua_pushstring(L, conf.sysop_name);
	lua_pushstring(L, name.sysname);
	lua_pushstring(L, name.machine);

	return 4;
}

int l_getUserHandle(lua_State *L) {
	lua_pushstring(L, gUser->loginname);

	return 1;
}

int l_getUserLocation(lua_State *L) {
	lua_pushstring(L, gUser->location);

	return 1;
}

int l_messageFound(lua_State *L) {
	int conference = lua_tointeger(L, 1);
	int area = lua_tointeger(L, 2);
	int id = lua_tointeger(L, 3);
/*	struct msg_t *z; */
	int z;

	struct msg_base_t *mb;

	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, conference);
	assert(mc != NULL);
	struct mail_area *ma = ptr_vector_get(&mc->mail_areas, area);
	assert(ma != NULL);
	mb = open_message_base(conference, area);


	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		lua_pushnumber(L, 0);
		return 1;
	}

	z = get_active_msg_count(mb);

	close_message_base(mb);
	if (id < z) {
		lua_pushnumber(L, 1);
		return 1;
	}

	lua_pushnumber(L, 0);
	return 1;
}

int l_readMessageHdr(lua_State *L) {
	int conference = lua_tointeger(L, 1);
	int area = lua_tointeger(L, 2);
	int id = lua_tointeger(L, 3);
	int z;

	struct msg_base_t *mb;
	struct msg_t *msg;

	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, conference);
	assert(mc != NULL);
	struct mail_area *ma = ptr_vector_get(&mc->mail_areas, area);
	assert(ma != NULL);
	mb = open_message_base(conference, area);

	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		return 0;
	}

	msg = load_message_hdr_offset(mb, id);

	close_message_base(mb);


	if (msg == NULL) {
		lua_pushstring(L, "Nobody");
		lua_pushstring(L, "Nobody");
		lua_pushstring(L, "Nothing");
		return 3;
	}


	lua_pushstring(L, msg->from);
	lua_pushstring(L, msg->to);
	lua_pushstring(L, msg->subject);

	free_message_hdr(msg);

	return 3;
}

int l_readMessage(lua_State *L) {
	int conference = lua_tointeger(L, 1);
	int area = lua_tointeger(L, 2);
	int id = lua_tointeger(L, 3);
	int z;

	struct msg_t *msg;
	struct msg_base_t *mb;

	char *body = NULL;

	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, conference);
	assert(mc != NULL);
	struct mail_area *ma = ptr_vector_get(&mc->mail_areas, area);
	assert(ma != NULL);

	mb = open_message_base(conference, area);

	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		return 0;
	}

	msg = load_message_hdr_offset(mb, id);
	if (msg == NULL) {
		dolog("Failed to read msg header: %d", z);
		close_message_base(mb);
		body = strdup("No Message");
	} else {
		body = load_message_text(mb, msg);
		if (body == NULL) {
			body = strdup("No Message");
		}
		free_message_hdr(msg);
		close_message_base(mb);
	}
	lua_pushstring(L, body);

	free(body);

	return 1;
}

int l_dataPath(lua_State *L) {
	char buffer[PATH_MAX];
	struct stat s;
	snprintf(buffer, PATH_MAX, "%s/data/", conf.script_path);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	lua_pushstring(L, buffer);

	return 1;
}

int l_tempPath(lua_State *L) {
	char buffer[PATH_MAX];
	struct stat s;
	snprintf(buffer, PATH_MAX, "%s/node%d/lua/", conf.bbs_path, mynode);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	lua_pushstring(L, buffer);

	return 1;
}

int l_userSecurity(lua_State *L) {
	lua_pushnumber(L, gUser->sec_level);
	return 1;
}

int l_postMessage(lua_State *L) {
	int confr = lua_tointeger(L, 1);
	int area = lua_tointeger(L, 2);
	time_t dwritten = utc_to_local(time(NULL));
	const char *to = lua_tostring(L, 3);
	const char *from = lua_tostring(L, 4);
	const char *subject = lua_tostring(L, 5);
	const char *body = lua_tostring(L, 6);
	int sem_fd;
	uuid_t mnet_msgid;
	uuid_t qwk_msgid;
	char qwkuuid[38];
	char buffer[256];
	struct msg_base_t *mb;
	int z;
	int j;
	int i;
	char *tagline;
	struct utsname name;

	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, confr);
	assert(mc != NULL);
	struct mail_area *ma = ptr_vector_get(&mc->mail_areas, area);
	assert(ma != NULL);

	uname(&name);
	tagline = conf.default_tagline;
	if (mc->tagline != NULL) {
		tagline = mc->tagline;
	}

	if (mc->nettype == NETWORK_FIDO) {
		if (mc->fidoaddr->point == 0) {
			snprintf(buffer, sizeof buffer, "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d)\r",
			         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
			         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node);
		} else {
			snprintf(buffer, sizeof buffer, "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d.%d)\r",
			         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
			         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node, mc->fidoaddr->point);
		}
	} else if (mc->nettype == NETWORK_MAGI) {
		snprintf(buffer, sizeof buffer, "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (@%d)\r",
		         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
		         mc->maginode);
	} else if (mc->nettype == NETWORK_QWK) {
		snprintf(buffer, sizeof buffer, "\r---\r * MagickaBBS * %s\r",
		         tagline);
	} else {
		snprintf(buffer, sizeof buffer, "\r");
	}

	stralloc sa = EMPTY_STRALLOC;
	stralloc_ready(&sa, strlen(body) + 2 + strlen(buffer));
	for (const char *p = body; *p != '\0'; ++p)
		if (*p != '\n')
			stralloc_append1(&sa, *p);
	stralloc_cats(&sa, buffer);
	stralloc_0(&sa);
	char *msg = sa.s;

	mb = open_message_base(confr, area);

	if (mb != NULL) {
		write_message(mb, to, from, subject, msg, NULL, NULL, NULL, 1);
		close_message_base(mb);
	}

	return 0;
}

void lua_push_cfunctions(lua_State *L) {
	lua_pushcfunction(L, l_bbsWString);
	lua_setglobal(L, "bbs_write_string");
	lua_pushcfunction(L, l_bbsRString);
	lua_setglobal(L, "bbs_read_string");
	lua_pushcfunction(L, l_bbsDisplayAnsiPause);
	lua_setglobal(L, "bbs_display_ansi_pause");
	lua_pushcfunction(L, l_bbsDisplayAnsi);
	lua_setglobal(L, "bbs_display_ansi");
	lua_pushcfunction(L, l_bbsRChar);
	lua_setglobal(L, "bbs_read_char");
	lua_pushcfunction(L, l_bbsVersion);
	lua_setglobal(L, "bbs_version");
	lua_pushcfunction(L, l_bbsNode);
	lua_setglobal(L, "bbs_node");
	lua_pushcfunction(L, l_bbsReadLast10);
	lua_setglobal(L, "bbs_read_last10");
	lua_pushcfunction(L, l_bbsGetEmailCount);
	lua_setglobal(L, "bbs_get_emailcount");
	lua_pushcfunction(L, l_bbsMailScan);
	lua_setglobal(L, "bbs_mail_scan");
	lua_pushcfunction(L, l_bbsRunDoor);
	lua_setglobal(L, "bbs_run_door");
	lua_pushcfunction(L, l_bbsTimeLeft);
	lua_setglobal(L, "bbs_time_left");
	lua_pushcfunction(L, l_getMailAreaInfo);
	lua_setglobal(L, "bbs_cur_mailarea_info");
	lua_pushcfunction(L, l_getFileAreaInfo);
	lua_setglobal(L, "bbs_cur_filearea_info");
	lua_pushcfunction(L, l_bbsDisplayAutoMsg);
	lua_setglobal(L, "bbs_display_automsg");
	lua_pushcfunction(L, l_getBBSInfo);
	lua_setglobal(L, "bbs_get_info");
	lua_pushcfunction(L, l_bbsFileScan);
	lua_setglobal(L, "bbs_file_scan");
	lua_pushcfunction(L, l_bbsFullMailScan);
	lua_setglobal(L, "bbs_full_mail_scan");
	lua_pushcfunction(L, l_bbsFullEmailScan);
	lua_setglobal(L, "bbs_full_email_scan");
	lua_pushcfunction(L, l_getUserHandle);
	lua_setglobal(L, "bbs_get_userhandle");
	lua_pushcfunction(L, l_getUserLocation);
	lua_setglobal(L, "bbs_get_userlocation");
	lua_pushcfunction(L, l_messageFound);
	lua_setglobal(L, "bbs_message_found");
	lua_pushcfunction(L, l_readMessageHdr);
	lua_setglobal(L, "bbs_read_message_hdr");
	lua_pushcfunction(L, l_readMessage);
	lua_setglobal(L, "bbs_read_message");
	lua_pushcfunction(L, l_tempPath);
	lua_setglobal(L, "bbs_temp_path");
	lua_pushcfunction(L, l_postMessage);
	lua_setglobal(L, "bbs_post_message");
	lua_pushcfunction(L, l_dataPath);
	lua_setglobal(L, "bbs_data_path");
	lua_pushcfunction(L, l_userSecurity);
	lua_setglobal(L, "bbs_user_security");
	lua_pushcfunction(L, l_bbsPersonalMailScan);
	lua_setglobal(L, "bbs_personal_mail_scan");
	lua_pushcfunction(L, l_displayBlog);
	lua_setglobal(L, "bbs_display_blog");
	lua_pushcfunction(L, l_ipAddress);
	lua_setglobal(L, "bbs_ip_address");
	lua_pushcfunction(L, l_ipInfo);
	lua_setglobal(L, "bbs_ip_info");
	lua_pushcfunction(L, l_getBlogEntryCount);
	lua_setglobal(L, "bbs_blog_entry_count");
	lua_pushcfunction(L, l_getBlogEntry);
	lua_setglobal(L, "bbs_blog_entry");
	lua_pushcfunction(L, l_getBlogAuthor);
	lua_setglobal(L, "bbs_blog_author");
	lua_pushcfunction(L, l_getBlogTitle);
	lua_setglobal(L, "bbs_blog_title");
	lua_pushcfunction(L, l_getBlogDate);
	lua_setglobal(L, "bbs_blog_date");
}

void do_lua_script(char *script) {
	lua_State *L;
	char buffer[PATH_MAX];
	struct stat s;
	int ret;

	if (script == NULL) {
		return;
	}

	if (script[0] == '/') {
		snprintf(buffer, sizeof buffer, "%s.lua", script);
	} else {
		snprintf(buffer, sizeof buffer, "%s/%s.lua", conf.script_path, script);
	}

	if (stat(buffer, &s) != 0) {
		return;
	}

	L = luaL_newstate();
	luaL_openlibs(L); 
/*	luaL_newlib(L); */
	lua_push_cfunctions(L);
	ret = luaL_dofile(L, buffer);
	if(ret != 0){
  		dolog("Error calling luaL_dofile() Error Code 0x%x",ret);
  		dolog("Error: %s", lua_tostring(L,-1));
	}
	lua_close(L);
}
