#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "bbs.h"

extern struct bbs_config conf;
extern struct user_record *gUser;

char *nl_get_bbsname(struct fido_addr *addr, char *domain) {
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char buffer[PATH_MAX];
	char *ret;
	char *sql_buf = "SELECT bbsname FROM nodelist WHERE nodeno=? AND domain=?";

	snprintf(buffer, PATH_MAX, "%s/nodelists.sq3", conf.bbs_path);

	rc = sqlite3_open(buffer, &db);

	if (rc != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(db));
		return strdup("Unknown");
	}
	sqlite3_busy_timeout(db, 5000);

	rc = sqlite3_prepare_v2(db, sql_buf, -1, &res, 0);

	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return strdup("Unknown");
	}

	if (addr->point != 0) {
		// no support for point addresses yet.
		return strdup("Unknown");
	}
	snprintf(buffer, PATH_MAX, "%d:%d/%d", addr->zone, addr->net, addr->node);

	sqlite3_bind_text(res, 1, buffer, -1, 0);
	sqlite3_bind_text(res, 2, domain, -1, 0);

	if (sqlite3_step(res) != SQLITE_ROW) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return strdup("Unknown");
	}
	ret = strdup(sqlite3_column_text(res, 0));

	sqlite3_finalize(res);
	sqlite3_close(db);
	return ret;
}

struct nl_temp {
	char *address;
	char *location;
	char *sysop;
	char *bbsname;
};

void nl_browser() {
	int entry_count = 0;
	struct nl_temp **entries;
	struct ptr_vector vec;
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char buffer[PATH_MAX];
	char *ret;
	char *sql_buf = "SELECT nodeno,location,sysop,bbsname FROM nodelist WHERE domain=?";
	int i;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;

	// load nodelist
	snprintf(buffer, PATH_MAX, "%s/nodelists.sq3", conf.bbs_path);

	rc = sqlite3_open(buffer, &db);

	if (rc != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(db));
		return;
	}
	sqlite3_busy_timeout(db, 5000);

	rc = sqlite3_prepare_v2(db, sql_buf, -1, &res, 0);

	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return;
	}

	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, gUser->cur_mail_conf);
	assert(mc != NULL);
	sqlite3_bind_text(res, 1, mc->domain, -1, 0);

	init_ptr_vector(&vec);
	while (sqlite3_step(res) == SQLITE_ROW) {
		struct nl_temp *entry = (struct nl_temp *)malloz(sizeof(struct nl_temp));
		entry->address = strdup(sqlite3_column_text(res, 0));
		entry->location = strdup(sqlite3_column_text(res, 1));
		entry->sysop = strdup(sqlite3_column_text(res, 2));
		entry->bbsname = strdup(sqlite3_column_text(res, 3));
		ptr_vector_append(&vec, entry);
	}
	entry_count = ptr_vector_len(&vec);
	entries = (struct nl_temp **)consume_ptr_vector(&vec);

	sqlite3_finalize(res);
	sqlite3_close(db);

	if (entry_count == 0) {
		return;
	}

	while (1) {
		if (redraw) {
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(145));
			s_printf(get_string(146));
			for (i = start; i < start + 22 && i < entry_count; i++) {
				if (i == selected) {
					s_printf(get_string(147), i - start + 2, i, entries[i]->address, entries[i]->bbsname);
				} else {
					s_printf(get_string(261), i - start + 2, i, entries[i]->address, entries[i]->bbsname);
				}
			}
			s_printf("\e[%d;5H", selected - start + 2);
			redraw = 0;
		}
		c = s_getchar();
		if (tolower(c) == 'q') {
			break;
		} else if (c == 27) {
			c = s_getchar();
			if (c == 91) {
				c = s_getchar();
				if (c == 66) {
					// down
					if (selected + 1 >= start + 22) {
						start += 22;
						if (start >= entry_count) {
							start = entry_count - 22;
						}
						redraw = 1;
					}
					selected++;
					if (selected >= entry_count) {
						selected = entry_count - 1;
					} else {
						if (!redraw) {
							s_printf(get_string(261), selected - start + 1, selected - 1, entries[selected - 1]->address, entries[selected - 1]->bbsname);
							s_printf(get_string(147), selected - start + 2, selected, entries[selected]->address, entries[selected]->bbsname);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 65) {
					// up
					if (selected - 1 < start) {
						start -= 22;
						if (start < 0) {
							start = 0;
						}
						redraw = 1;
					}
					selected--;
					if (selected < 0) {
						selected = 0;
					} else {
						if (!redraw) {
							s_printf(get_string(147), selected - start + 2, selected, entries[selected]->address, entries[selected]->bbsname);
							s_printf(get_string(261), selected - start + 3, selected + 1, entries[selected + 1]->address, entries[selected + 1]->bbsname);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 75) {
					// END KEY
					selected = entry_count - 1;
					start = entry_count - 22;
					if (start < 0) {
						start = 0;
					}
					redraw = 1;
				} else if (c == 72) {
					// HOME KEY
					selected = 0;
					start = 0;
					redraw = 1;
				} else if (c == 86 || c == '5') {
					if (c == '5') {
						s_getchar();
					}
					// PAGE UP
					selected = selected - 22;
					if (selected < 0) {
						selected = 0;
					}
					start = selected;
					redraw = 1;
				} else if (c == 85 || c == '6') {
					if (c == '6') {
						s_getchar();
					}
					// PAGE DOWN
					selected = selected + 22;
					if (selected >= entry_count) {
						selected = entry_count - 1;
					}
					start = selected;
					redraw = 1;
				}
			}
		} else if (c == 13) {
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(262), entries[selected]->address);
			s_printf(get_string(263));
			s_printf(get_string(264), entries[selected]->bbsname);
			s_printf(get_string(265), entries[selected]->sysop);
			s_printf(get_string(266), entries[selected]->location);
			s_printf(get_string(267));
			s_printf(get_string(185));
			s_getc();
			s_printf("\r\n");
			redraw = 1;
		}
	}
	for (i = 0; i < entry_count; i++) {
		free(entries[i]->address);
		free(entries[i]->bbsname);
		free(entries[i]->sysop);
		free(entries[i]->location);
		free(entries[i]);
	}
	free(entries);
}
