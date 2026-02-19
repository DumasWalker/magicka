#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"

#include "bbs.h"

#define MENU_SUBMENU 1
#define MENU_LOGOFF 2
#define MENU_PREVMENU 3
#define MENU_AUTOMESSAGE 4
#define MENU_TEXTFILES 5
#define MENU_CHATSYSTEM 6
#define MENU_BBSLIST 7
#define MENU_LISTUSERS 8
#define MENU_BULLETINS 9
#define MENU_LAST10 10
#define MENU_SETTINGS 11
#define MENU_DOOR 12
#define MENU_MAILSCAN 13
#define MENU_READMAIL 14
#define MENU_POSTMESSAGE 15
#define MENU_CHOOSEMAILCONF 16
#define MENU_CHOOSEMAILAREA 17
#define MENU_SENDEMAIL 18
#define MENU_LISTEMAIL 19
#define MENU_NEXTMAILCONF 20
#define MENU_PREVMAILCONF 21
#define MENU_NEXTMAILAREA 22
#define MENU_PREVMAILAREA 23
#define MENU_BLUEWAVEDOWN 24
#define MENU_BLUEWAVEUP 25
#define MENU_CHOOSEFILEDIR 26
#define MENU_CHOOSEFILESUB 27
#define MENU_LISTFILES 28
#define MENU_UPLOAD 29
#define MENU_DOWNLOAD 30
#define MENU_CLEARTAGGEDFILES 31
#define MENU_NEXTFILEDIR 32
#define MENU_PREVFILEDIR 33
#define MENU_NEXTFILESUB 34
#define MENU_PREVFILESUB 35
#define MENU_LISTMESSAGES 36
#define MENU_DOSCRIPT 37
#define MENU_SENDNODEMSG 38
#define MENU_SUBUNSUBCONF 39
#define MENU_RESETPOINTERS 40
#define MENU_RESETALLPOINTERS 41
#define MENU_FILESCAN 42
#define MENU_FULLMAILSCAN 43
#define MENU_FILESEARCH 44
#define MENU_DISPTXTFILE 45
#define MENU_DISPTXTFILEPAUSE 46
#define MENU_GENWWWURLS 47
#define MENU_NLBROWSER 48
#define MENU_SENDFEEDBACK 49
#define MENU_BLOGDISPLAY 50
#define MENU_BLOGWRITE 51
#define MENU_QWKDOWN 52
#define MENU_QWKUP 53
#define MENU_WHOSONLINE 54

extern struct bbs_config conf;
extern struct user_record *gUser;
extern int mynode;

struct menu_command {
	int command;
	char *data;
};

struct menu_item {
	char hotkey;
	struct ptr_vector commands;
	int seclevel;
	struct ptr_vector req_flags;
	struct ptr_vector not_flags;
};

struct key_value_map {
	const char *key;
	int value;
};

static const struct key_value_map commands[] = {
    {"SUBMENU", MENU_SUBMENU},
    {"LOGOFF", MENU_LOGOFF},
    {"PREVMENU", MENU_PREVMENU},
    {"AUTOMESSAGE", MENU_AUTOMESSAGE},
    {"TEXTFILES", MENU_TEXTFILES},
    {"CHATSYSTEM", MENU_CHATSYSTEM},
    {"BBSLIST", MENU_BBSLIST},
    {"LISTUSERS", MENU_LISTUSERS},
    {"BULLETINS", MENU_BULLETINS},
    {"LAST10CALLERS", MENU_LAST10},
    {"SETTINGS", MENU_SETTINGS},
    {"RUNDOOR", MENU_DOOR},
    {"MAILSCAN", MENU_MAILSCAN},
    {"READMAIL", MENU_READMAIL},
    {"POSTMESSAGE", MENU_POSTMESSAGE},
    {"CHOOSEMAILCONF", MENU_CHOOSEMAILCONF},
    {"CHOOSEMAILAREA", MENU_CHOOSEMAILAREA},
    {"SENDEMAIL", MENU_SENDEMAIL},
    {"LISTEMAIL", MENU_LISTEMAIL},
    {"NEXTMAILCONF", MENU_NEXTMAILCONF},
    {"PREVMAILCONF", MENU_PREVMAILCONF},
    {"NEXTMAILAREA", MENU_NEXTMAILAREA},
    {"PREVMAILAREA", MENU_PREVMAILAREA},
    {"BLUEWAVEDOWNLOAD", MENU_BLUEWAVEDOWN},
    {"BLUEWAVEUPLOAD", MENU_BLUEWAVEUP},
    {"CHOOSEFILEDIR", MENU_CHOOSEFILEDIR},
    {"CHOOSEFILESUB", MENU_CHOOSEFILESUB},
    {"LISTFILES", MENU_LISTFILES},
    {"UPLOAD", MENU_UPLOAD},
    {"DOWNLOAD", MENU_DOWNLOAD},
    {"CLEARTAGGED", MENU_CLEARTAGGEDFILES},
    {"NEXTFILEDIR", MENU_NEXTFILEDIR},
    {"PREVFILEDIR", MENU_PREVFILEDIR},
    {"NEXTFILESUB", MENU_NEXTFILESUB},
    {"PREVFILESUB", MENU_PREVFILESUB},
    {"LISTMESSAGES", MENU_LISTMESSAGES},
    {"DOSCRIPT", MENU_DOSCRIPT},
    {"SENDNODEMSG", MENU_SENDNODEMSG},
    {"SUBUNSUBCONF", MENU_SUBUNSUBCONF},
    {"RESETMSGPTRS", MENU_RESETPOINTERS},
    {"RESETALLMSGPTRS", MENU_RESETALLPOINTERS},
    {"FILESCAN", MENU_FILESCAN},
    {"FULLMAILSCAN", MENU_FULLMAILSCAN},
    {"FILESEARCH", MENU_FILESEARCH},
    {"DISPLAYTXTFILE", MENU_DISPTXTFILE},
    {"DISPLAYTXTPAUSE", MENU_DISPTXTFILEPAUSE},
    {"GENWWWURLS", MENU_GENWWWURLS},
    {"NLBROWSER", MENU_NLBROWSER},
    {"SENDFEEDBACK", MENU_SENDFEEDBACK},
    {"BLOGDISPLAY", MENU_BLOGDISPLAY},
    {"BLOGWRITE", MENU_BLOGWRITE},
    {"QWKDOWNLOAD", MENU_QWKDOWN},
    {"QWKUPLOAD", MENU_QWKUP},
	{"WHOSONLINE", MENU_WHOSONLINE}};

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

int cmd2cmd(const char *cmd) {
	for (size_t i = 0; i < ARRAY_SIZE(commands); ++i)
		if (strncmp(cmd, commands[i].key, strlen(commands[i].key)) == 0)
			return commands[i].value;
	return -1;
}

static int badmenu(const char *menufile) {
	s_printf("Bad menu file! %s\r\n", menufile);
	return 0;
}

static void free_menu(struct ptr_vector *menu) {
	assert(menu != NULL);
	for (size_t i = 0; i < ptr_vector_len(menu); ++i) {
		struct menu_item *item = ptr_vector_get(menu, i);
		assert(item != NULL);
		for (size_t j = 0; j < ptr_vector_len(&item->commands); ++j) {
			struct menu_command *cmd = ptr_vector_get(&item->commands, j);
			assert(cmd != NULL);
			free(cmd->data);
		}
		ptr_vector_apply(&item->req_flags, free);
		destroy_ptr_vector(&item->req_flags);
		ptr_vector_apply(&item->not_flags, free);
		destroy_ptr_vector(&item->not_flags);
		ptr_vector_apply(&item->commands, free);
		destroy_ptr_vector(&item->commands);
	}
	ptr_vector_apply(menu, free);
	destroy_ptr_vector(menu);
}

int menu_system(char *menufile) {
	FILE *fptr;
	char buffer[PATH_MAX];
	struct ptr_vector menu = EMPTY_PTR_VECTOR;
	struct menu_item *this_menu = NULL;
	struct menu_command *this_command = NULL;
	char *lua_script = NULL;
	int do_lua_menu = 0;
	char *ansi_file = NULL;
	int i;
	int j;
	int k;
	int m;
	struct stat s;
	char *lRet;
	lua_State *L;
	int result;
	int doquit = 0;
	char c;
	int clearscreen = 0;
	char confirm;
	char *msg;
	char *mserver;
	int mport;

	dolog("%s is loading menu: %s", gUser->loginname, menufile);
	broadcast("USER: %s; NODE:%d; STATUS: Browsing menu %s.", gUser->loginname, mynode, menufile);

	if (menufile[0] == '/') {
		snprintf(buffer, PATH_MAX, "%s.mnu", menufile);
	} else {
		snprintf(buffer, PATH_MAX, "%s/%s.mnu", conf.menu_path, menufile);
	}
	fptr = fopen(buffer, "r");
	if (!fptr)
		return badmenu(menufile);

	init_ptr_vector(&menu);
	while (fgets(buffer, sizeof buffer, fptr) != NULL && !feof(fptr)) {
		chomp(buffer);

		if (strncasecmp(buffer, "HOTKEY", 6) == 0) {
			this_menu = malloz(sizeof(struct menu_item));
			this_menu->hotkey = buffer[7];
			init_ptr_vector(&this_menu->commands);
			init_ptr_vector(&this_menu->req_flags);
			init_ptr_vector(&this_menu->not_flags);
			this_menu->seclevel = 0;
			ptr_vector_append(&menu, this_menu);
		} else if (strncasecmp(buffer, "COMMAND", 7) == 0) {
			if (this_menu == NULL)
				return badmenu(menufile);
			int cmd = cmd2cmd(buffer + 8);
			if (cmd < 0)
				continue;
			this_command = malloz(sizeof(struct menu_command));
			this_command->command = cmd;
			this_command->data = NULL;
			ptr_vector_append(&this_menu->commands, this_command);
		} else if (strncasecmp(buffer, "SECLEVEL", 8) == 0) {
			if (this_menu == NULL)
				return badmenu(menufile);
			this_menu->seclevel = atoi(buffer + 9);
		} else if (strncasecmp(buffer, "REQFLAG", 7) == 0) {
			if (this_menu == NULL)
				return badmenu(menufile);
			ptr_vector_append(&this_menu->req_flags, strdup(&buffer[8]));
		} else if (strncasecmp(buffer, "NOTFLAG", 7) == 0) {
			if (this_menu == NULL)
				return badmenu(menufile);
			ptr_vector_append(&this_menu->not_flags, strdup(&buffer[8]));
		} else if (strncasecmp(buffer, "DATA", 4) == 0) {
			if (this_command == NULL)
				return badmenu(menufile);
			free(this_command->data);
			this_command->data = strdup(buffer + 5);
		} else if (strncasecmp(buffer, "LUASCRIPT", 9) == 0) {
			free(lua_script);
			lua_script = strdup(buffer + 10);
		} else if (strncasecmp(buffer, "ANSIFILE", 8) == 0) {
			free(ansi_file);
			ansi_file = strdup(buffer + 9);
		} else if (strncasecmp(buffer, "CLEARSCREEN", 11) == 0) {
			clearscreen = 1;
		}
	}
	fclose(fptr);

	do_lua_menu = 0;

	if (lua_script != NULL) {
		if (conf.script_path != NULL && lua_script[0] != '/') {
			snprintf(buffer, PATH_MAX, "%s/%s.lua", conf.script_path, lua_script);
			do_lua_menu = 1;
		} else if (lua_script[0] == '/') {
			snprintf(buffer, PATH_MAX, "%s.lua", lua_script);
			do_lua_menu = 1;
		}

		if (do_lua_menu) {
			if (stat(buffer, &s) == 0) {
				L = luaL_newstate();
				luaL_openlibs(L);
				lua_push_cfunctions(L);
				luaL_loadfile(L, buffer);
				do_lua_menu = 1;
				result = lua_pcall(L, 0, 1, 0);
				if (result) {
					dolog("Failed to run script: %s", lua_tostring(L, -1));
					do_lua_menu = 0;
				}
			} else {
				do_lua_menu = 0;
			}
		}
	}

	while (!doquit) {
		if (gUser->nodemsgs) {
			snprintf(buffer, sizeof buffer, "%s/node%d/nodemsg.txt", conf.bbs_path, mynode);

			if (stat(buffer, &s) == 0) {
				fptr = fopen(buffer, "r");
				if (fptr) {
					s_printf("\e[2J\e[1;1H");
					s_printf(get_string(319));
					s_printf(get_string(320));
					fgets(buffer, PATH_MAX, fptr);
					while (!feof(fptr)) {
						chomp(buffer);
						s_printf("\r\n%s\r\n", buffer);
						fgets(buffer, sizeof buffer, fptr);
					}
					fclose(fptr);
					snprintf(buffer, sizeof buffer, "%s/node%d/nodemsg.txt", conf.bbs_path, mynode);
					unlink(buffer);
					s_printf(get_string(320));
					s_printf(get_string(6));
					c = s_getc();
					s_printf("\e[2J\e[1;1H");
				}
			}
		}

		if (clearscreen) {
			s_printf("\e[2J\e[1;1H");
		}

		if (do_lua_menu == 0) {
			if (ansi_file != NULL) {
				s_displayansi(ansi_file);
			}
			s_printf(get_string(142), gUser->timeleft);
			c = s_getc();
		} else {
			lua_getglobal(L, "menu");
			result = lua_pcall(L, 0, 1, 0);
			if (result) {
				dolog("Failed to run script: %s", lua_tostring(L, -1));
				do_lua_menu = 0;
				lua_close(L);
				continue;
			}
			lRet = (char *)lua_tostring(L, -1);
			c = lRet[0];
			lua_pop(L, 1);
		}

		for (size_t i = 0; i < ptr_vector_len(&menu); i++) {
			struct menu_item *item = ptr_vector_get(&menu, i);
			if (tolower(item->hotkey) == tolower(c)) {
				if (check_security(gUser, item->seclevel, &item->req_flags, &item->not_flags)) {
					for (size_t j = 0; j < ptr_vector_len(&item->commands); ++j) {
						struct menu_command *cmd = ptr_vector_get(&item->commands, j);
						switch (cmd->command) {
							case MENU_SUBMENU:
								doquit = menu_system(cmd->data);
								if (doquit == 1) {
									// free menus
									free_menu(&menu);
									free(ansi_file);
									if (do_lua_menu)
										lua_close(L);
									free(lua_script);
									return doquit;
								}
								break;
							case MENU_LOGOFF:
								free(ansi_file);
								if (do_lua_menu)
									lua_close(L);
								free(lua_script);
								free_menu(&menu);
								return 1;
							case MENU_PREVMENU:
								if (do_lua_menu)
									lua_close(L);
								free(lua_script);
								free(ansi_file);
								free_menu(&menu);
								return 0;
							case MENU_AUTOMESSAGE:
								broadcast("USER: %s; NODE:%d; STATUS: Viewing/Changing Automessage.", gUser->loginname, mynode);
								automessage();
								break;
							case MENU_TEXTFILES:
								broadcast("USER: %s; NODE:%d; STATUS: Browsing Textfiles.", gUser->loginname, mynode);
								display_textfiles();
								break;
							case MENU_CHATSYSTEM:
								broadcast("USER: %s; NODE:%d; STATUS: In Chat System.", gUser->loginname, mynode);

								mserver = NULL;
								if (cmd->data != NULL) {
									if (strrchr(cmd->data, ':') != NULL) {
										mserver = strdup(cmd->data);
										mport = atoi(strrchr(cmd->data, ':') + 1);
										*(strrchr(mserver, ':')) = '\0';
									}
								} else {
									if (conf.mgchat_server != NULL)
										mserver = strdup(conf.mgchat_server);
									mport = conf.mgchat_port;
								}

								if (mserver == NULL || conf.mgchat_bbstag == NULL) {

									s_putstring(get_string(49));
								} else {
									chat_system(gUser, mserver, mport);
								}
								free(mserver);
								break;
							case MENU_BBSLIST:
								broadcast("USER: %s; NODE:%d; STATUS: Browsing BBS List.", gUser->loginname, mynode);
								bbs_list(gUser);
								break;
							case MENU_LISTUSERS:
								broadcast("USER: %s; NODE:%d; STATUS: Browsing User List.", gUser->loginname, mynode);
								list_users(gUser);
								break;
							case MENU_BULLETINS:
								broadcast("USER: %s; NODE:%d; STATUS: Reading Bulletins.", gUser->loginname, mynode);
								display_bulletins();
								break;
							case MENU_LAST10:
								broadcast("USER: %s; NODE:%d; STATUS: Viewing Last 10 Callers.", gUser->loginname, mynode);
								display_last10_callers(gUser);
								break;
							case MENU_SETTINGS:
								settings_menu(gUser);
								break;
							case MENU_DOOR: {
								for (m = 0; m < ptr_vector_len(&conf.doors); m++) {
									struct door_config *door = ptr_vector_get(&conf.doors, m);
									if (strcasecmp(cmd->data, door->name) == 0) {
										dolog("%s launched door %s, on node %d", gUser->loginname, door->name, mynode);
										broadcast("USER: %s; NODE:%d; STATUS: Executing Door %s.", gUser->loginname, mynode, door->name);
										rundoor(gUser, door->command, door->stdio, door->codepage);
										dolog("%s returned from door %s, on node %d", gUser->loginname, door->name, mynode);
										break;
									}
								}
							} break;
							case MENU_MAILSCAN:
								broadcast("USER: %s; NODE:%d; STATUS: Performing Mail Scan.", gUser->loginname, mynode);
								mail_scan(gUser);
								break;
							case MENU_READMAIL:
								broadcast("USER: %s; NODE:%d; STATUS: Reading Mail.", gUser->loginname, mynode);
								read_mail(gUser);
								break;
							case MENU_POSTMESSAGE:
								broadcast("USER: %s; NODE:%d; STATUS: Posting a Message.", gUser->loginname, mynode);
								post_message(gUser);
								break;
							case MENU_CHOOSEMAILCONF:
								broadcast("USER: %s; NODE:%d; STATUS: Choosing Mail Conference.", gUser->loginname, mynode);
								gUser->cur_mail_conf = choose_conference();
								gUser->cur_mail_area = 0;
								break;
							case MENU_CHOOSEMAILAREA:
								broadcast("USER: %s; NODE:%d; STATUS: Choosing Mail Area.", gUser->loginname, mynode);
								gUser->cur_mail_area = choose_area(gUser->cur_mail_conf);
								break;
							case MENU_SENDEMAIL:
								broadcast("USER: %s; NODE:%d; STATUS: Sending an Email.", gUser->loginname, mynode);
								send_email(gUser);
								break;
							case MENU_LISTEMAIL:
								broadcast("USER: %s; NODE:%d; STATUS: Browsing their Emails.", gUser->loginname, mynode);
								list_emails(gUser);
								break;
							case MENU_NEXTMAILCONF:
								next_mail_conf(gUser);
								break;
							case MENU_PREVMAILCONF:
								prev_mail_conf(gUser);
								break;
							case MENU_NEXTMAILAREA:
								next_mail_area(gUser);
								break;
							case MENU_PREVMAILAREA:
								prev_mail_area(gUser);
								break;
							case MENU_BLUEWAVEDOWN:
								broadcast("USER: %s; NODE:%d; STATUS: Downloading Bluewave Packet.", gUser->loginname, mynode);
								bwave_create_packet();
								break;
							case MENU_BLUEWAVEUP:
								broadcast("USER: %s; NODE:%d; STATUS: Uploading Bluewave Packet.", gUser->loginname, mynode);
								bwave_upload_reply();
								break;
							case MENU_CHOOSEFILEDIR:
								broadcast("USER: %s; NODE:%d; STATUS: Choosing a file directory.", gUser->loginname, mynode);
								choose_directory();
								break;
							case MENU_CHOOSEFILESUB:
								broadcast("USER: %s; NODE:%d; STATUS: Choosing a file sub-directory.", gUser->loginname, mynode);
								choose_subdir();
								break;
							case MENU_LISTFILES:
								broadcast("USER: %s; NODE:%d; STATUS: Browsing Files.", gUser->loginname, mynode);
								list_files(gUser);
								break;
							case MENU_UPLOAD: {
								struct file_directory *dir = ptr_vector_get(&conf.file_directories, gUser->cur_file_dir);
								assert(dir != NULL);
								struct file_sub *sub = ptr_vector_get(&dir->file_subs, gUser->cur_file_sub);
								assert(sub != NULL);
								if (gUser->sec_level >= sub->upload_sec_level) {
									broadcast("USER: %s; NODE:%d; STATUS: Uploading a File.", gUser->loginname, mynode);
									upload(gUser);
								} else {
									s_printf(get_string(84));
								}
								break;
							}
							case MENU_DOWNLOAD:
								broadcast("USER: %s; NODE:%d; STATUS: Downloading Files.", gUser->loginname, mynode);
								download(gUser);
								break;
							case MENU_CLEARTAGGEDFILES:
								clear_tagged_files();
								break;
							case MENU_NEXTFILEDIR:
								next_file_dir(gUser);
								break;
							case MENU_PREVFILEDIR:
								prev_file_dir(gUser);
								break;
							case MENU_NEXTFILESUB:
								next_file_sub(gUser);
								break;
							case MENU_PREVFILESUB:
								prev_file_sub(gUser);
								break;
							case MENU_LISTMESSAGES:
								list_messages(gUser);
								break;
							case MENU_DOSCRIPT:
								broadcast("USER: %s; NODE:%d; STATUS: Executing a script %s.", gUser->loginname, mynode, cmd->data);
								do_lua_script(cmd->data);
								break;
							case MENU_SENDNODEMSG:
								broadcast("USER: %s; NODE:%d; STATUS: Sending a node Message.", gUser->loginname, mynode);
								send_node_msg();
								break;
							case MENU_SUBUNSUBCONF:
								broadcast("USER: %s; NODE:%d; STATUS: Subscribing to conferences.", gUser->loginname, mynode);
								msg_conf_sub_bases();
								break;
							case MENU_RESETPOINTERS:
								{
									int confr = choose_conference();
									int area = choose_area(confr);

									s_printf("\e[2J\e[1;1H");

									s_printf(get_string(229));
									s_readstring(buffer, 10);
									if (tolower(buffer[0]) == 'r') {
										k = -1;
										m = 1;
									} else if (tolower(buffer[0]) == 'u') {
										k = -1;
										m = 0;
									} else if (buffer[0] < '0' || buffer[0] > '9') {
										s_printf(get_string(39));
										break;
									} else {
										k = atoi(buffer) - 1;
									}

									msgbase_reset_pointers(confr, area, m, k);
								}
								break;
							case MENU_RESETALLPOINTERS:
								s_printf(get_string(230));
								confirm = s_getc();
								if (confirm == 'r' || confirm == 'R') {
									m = 1;
								} else if (confirm == 'u' || confirm == 'U') {
									m = 0;
								} else {
									s_printf(get_string(39));
									break;
								}
								msgbase_reset_all_pointers(m);
								break;
							case MENU_FILESCAN:
								broadcast("USER: %s; NODE:%d; STATUS: Doing a filescan.", gUser->loginname, mynode);
								file_scan();
								break;
							case MENU_FULLMAILSCAN:
								if (cmd->data != NULL) {
									if (strcasecmp(cmd->data, "PERSONAL") == 0) {
										broadcast("USER: %s; NODE:%d; STATUS: Scanning for personal mail.", gUser->loginname, mynode);
										full_mail_scan_personal(gUser);
									} else {
										broadcast("USER: %s; NODE:%d; STATUS: Scanning all mail.", gUser->loginname, mynode);
										full_mail_scan(gUser);
									}
								} else {
									full_mail_scan(gUser);
								}
								break;
							case MENU_FILESEARCH:
								broadcast("USER: %s; NODE:%d; STATUS: Executing a filesearch.", gUser->loginname, mynode);
								file_search();
								break;
							case MENU_DISPTXTFILE:
								if (cmd->data != NULL) {
									broadcast("USER: %s; NODE:%d; STATUS: Displaying Text File: %s.", gUser->loginname, mynode, cmd->data);
									s_displayansi_pause(cmd->data, 0);
								}
								break;
							case MENU_DISPTXTFILEPAUSE:
								if (cmd->data != NULL) {
									broadcast("USER: %s; NODE:%d; STATUS: Displaying Text File: %s.", gUser->loginname, mynode, cmd->data);
									s_displayansi_pause(cmd->data, 1);
								}
								s_printf(get_string(6));
								s_getc();
								break;
							case MENU_GENWWWURLS:
								genurls();
								break;
							case MENU_NLBROWSER:
								broadcast("USER: %s; NODE:%d; STATUS: Browsing the Nodelist.", gUser->loginname, mynode);
								nl_browser();
								break;
							case MENU_SENDFEEDBACK:
								if (check_user(conf.sysop_name)) {
									break;
								}
								broadcast("USER: %s; NODE:%d; STATUS: Sending feedback to Sysop.", gUser->loginname, mynode);
								msg = external_editor(gUser, conf.sysop_name, gUser->loginname, NULL, 0, NULL, "Feedback", 1, 0);
								if (msg != NULL) {
									commit_email(conf.sysop_name, "Feedback", msg);
									free(msg);
								}
								break;
							case MENU_BLOGDISPLAY:
								broadcast("USER: %s; NODE:%d; STATUS: Displaying Blog.", gUser->loginname, mynode);
								blog_display();
								break;
							case MENU_BLOGWRITE:
								broadcast("USER: %s; NODE:%d; STATUS: Writing a Blog Entry.", gUser->loginname, mynode);
								blog_write();
								break;
							case MENU_QWKDOWN:
								broadcast("USER: %s; NODE:%d; STATUS: Downloading QWK Packet.", gUser->loginname, mynode);
								qwk_create_packet();
								break;
							case MENU_QWKUP:
								broadcast("USER: %s; NODE:%d; STATUS: Uploading QWK Packet.", gUser->loginname, mynode);
								qwk_upload_reply();
								break;
							case MENU_WHOSONLINE:
								active_nodes();
								s_printf(get_string(6));
								s_getc();
								break;
							default:
								break;
						}
					}
					break;
				}
			}
		}
	}

	free(ansi_file);
	if (do_lua_menu)
		lua_close(L);
	free(lua_script);
	free_menu(&menu);

	return doquit;
}
