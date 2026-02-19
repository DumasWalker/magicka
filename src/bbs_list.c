#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <ctype.h>
#include "bbs.h"

extern struct bbs_config conf;
extern struct user_record *gUser;
struct bbs_list_entry_t {
	int id;
	char *bbsname;
	char *sysopname;
	char *location;
	char *software;
	char *url;
	int tport;
	int sport;
	char *comment;
	time_t verified;
	int owner;
};

int add_bbs(struct bbs_list_entry_t *new_entry) {
	char *create_sql = "CREATE TABLE IF NOT EXISTS bbslist ("
	                   "id INTEGER PRIMARY KEY,"
	                   "bbsname TEXT,"
	                   "sysop TEXT,"
					   "location TEXT,"
					   "software TEXT,"
	                   "url TEXT,"
					   "tport INGEGER,"
					   "sport INTEGER,"
					   "comment TEXT,"
					   "verified INTEGER,"
	                   "owner INTEGER);";

	char *insert_sql = "INSERT INTO bbslist (bbsname, sysop, location, software, url, tport, sport, comment, verified, owner) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	char bbsname[32];
	char sysop[32];
	char software[32];
	char url[64];
	char comment[64];
	char location[32];
	char buffer[PATH_MAX];
	int tport;
	int sport;
	time_t ver;

	char c;
	char *err_msg = 0;
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	int id;

	s_printf("\e[2J\e[1;1H");

	s_printf(get_string(28));
	s_readstring(bbsname, 32);

	s_printf(get_string(29));
	s_readstring(sysop, 32);

	s_printf(get_string(30));
	s_readstring(software, 32);

	s_printf(get_string(300));
	s_readstring(url, 64);

	s_printf(get_string(310));
	s_readstring(location, 32);

	s_printf(get_string(301));
	s_readstring(buffer, 5);

	tport = atoi(buffer);
	if (tport < 1 || tport > 65535) {
		tport = -1;
	}

	s_printf(get_string(302));
	s_readstring(buffer, 5);

	sport = atoi(buffer);
	if (sport < 1 || sport > 65535) {
		sport = -1;
	}

	s_printf(get_string(303));
	s_readstring(comment, 64);

	s_printf(get_string(31));
	s_printf(get_string(32));
	s_printf(get_string(33), bbsname);
	s_printf(get_string(34), sysop);
	s_printf(get_string(311), location);
	s_printf(get_string(35), software);
	s_printf(get_string(304), url);
	if (tport == -1) {
		s_printf(get_string(306));
	} else {
		s_printf(get_string(305), tport);
	}
	if (sport == -1) {
		s_printf(get_string(308));
	} else {
		s_printf(get_string(307), sport);
	}
	s_printf(get_string(309), comment);

	s_printf(get_string(36));
	s_printf(get_string(37));

	c = s_getc();
	if (tolower(c) == 'y') {
		snprintf(buffer, PATH_MAX, "%s/bbslist2.sq3", conf.bbs_path);

		rc = sqlite3_open(buffer, &db);

		if (rc != SQLITE_OK) {
			dolog("Cannot open database: %s", sqlite3_errmsg(db));
			return 0;
		}
		sqlite3_busy_timeout(db, 5000);
		rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
		if (rc != SQLITE_OK) {

			dolog("SQL error: %s", err_msg);

			sqlite3_free(err_msg);
			sqlite3_close(db);

			return 0;
		}

		rc = sqlite3_prepare_v2(db, insert_sql, -1, &res, 0);
		ver = time(NULL);

		if (rc == SQLITE_OK) {

			sqlite3_bind_text(res, 1, bbsname, -1, 0);
			sqlite3_bind_text(res, 2, sysop, -1, 0);
			sqlite3_bind_text(res, 3, location, -1, 0);
			sqlite3_bind_text(res, 4, software, -1, 0);
			sqlite3_bind_text(res, 5, url, -1, 0);
			sqlite3_bind_int(res, 6, tport);
			sqlite3_bind_int(res, 7, sport);
			sqlite3_bind_text(res, 8, comment, -1, 0);
			sqlite3_bind_int(res, 9, ver);
			sqlite3_bind_int(res, 10, gUser->id);
		} else {
			dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return 0;
		}

		rc = sqlite3_step(res);

		if (rc != SQLITE_DONE) {

			dolog("execution failed: %s", sqlite3_errmsg(db));
			sqlite3_finalize(res);
			sqlite3_close(db);
			return 0;
		}
		id = sqlite3_last_insert_rowid(db);

		sqlite3_finalize(res);
		sqlite3_close(db);
		s_printf(get_string(38));

		if (new_entry != NULL) {
			new_entry->id = id;
			new_entry->bbsname = strdup(bbsname);
			new_entry->sysopname = strdup(sysop);
			new_entry->software = strdup(software);
			new_entry->location = strdup(location);
			new_entry->url = strdup(url);
			new_entry->tport = tport;
			new_entry->sport = sport;
			new_entry->comment = strdup(comment);
			new_entry->verified = ver;
			new_entry->owner = gUser->id;
		}
		return 1;
	} else {
		s_printf(get_string(39));
		return 0;
	}
}

int delete_bbs(int id) {
	char buffer[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *sql = "SELECT bbsname FROM bbslist WHERE id=? and owner=?";
	char *dsql = "DELETE FROM bbslist WHERE id=?";
	char c;

	s_printf("\e[2J\e[1;1H");

	snprintf(buffer, PATH_MAX, "%s/bbslist2.sq3", conf.bbs_path);

	rc = sqlite3_open(buffer, &db);

	if (rc != SQLITE_OK) {
		return 0;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_int(res, 1, id);
		sqlite3_bind_int(res, 2, gUser->id);
	} else {
		sqlite3_close(db);
		s_printf(get_string(41));
		return 0;
	}
	if (sqlite3_step(res) == SQLITE_ROW) {
		s_printf(get_string(42), sqlite3_column_text(res, 0));
		sqlite3_finalize(res);
		c = s_getc();
		if (tolower(c) == 'y') {
			rc = sqlite3_prepare_v2(db, dsql, -1, &res, 0);
			if (rc == SQLITE_OK) {
				sqlite3_bind_int(res, 1, id);
			} else {
				sqlite3_close(db);
				s_printf(get_string(41));
				return 0;
			}
			sqlite3_step(res);
			s_printf(get_string(43));
			sqlite3_finalize(res);
			sqlite3_close(db);
			return 1;
		} else {
			s_printf(get_string(39));
			sqlite3_close(db);
			return 0;
		}
	} else {
		sqlite3_finalize(res);
		s_printf(get_string(44));
		sqlite3_close(db);
		return 0;
	}
}

void bbs_list() {
	int i;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;
	char buffer[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *sql = "SELECT id,bbsname,sysop,location,software,url,tport,sport,comment,verified,owner FROM bbslist";
	char *vsql = "UPDATE bbslist SET verified=? WHERE id=?";
	struct ptr_vector entries;
	int entrycount;
	struct bbs_list_entry_t *newentry;
	char *ownername;
	struct tm verified;

	init_ptr_vector(&entries);
	while (1) {
		entrycount = 0;
		snprintf(buffer, PATH_MAX, "%s/bbslist2.sq3", conf.bbs_path);

		rc = sqlite3_open(buffer, &db);

		if (rc != SQLITE_OK) {
			dolog("Cannot open database: %s", sqlite3_errmsg(db));
			return;
		}

		sqlite3_busy_timeout(db, 5000);
		rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
		if (rc != SQLITE_OK) {
			sqlite3_close(db);

		} else {
			while (sqlite3_step(res) == SQLITE_ROW) {
				struct bbs_list_entry_t *entry = malloz(sizeof(struct bbs_list_entry_t));
				entry->id = sqlite3_column_int(res, 0);
				entry->bbsname = strdup(sqlite3_column_text(res, 1));
				entry->sysopname = strdup(sqlite3_column_text(res, 2));
				entry->location = strdup(sqlite3_column_text(res, 3));
				entry->software = strdup(sqlite3_column_text(res, 4));
				entry->url = strdup(sqlite3_column_text(res, 5));
				entry->tport = sqlite3_column_int(res, 6);
				entry->sport = sqlite3_column_int(res, 7);
				entry->comment = strdup(sqlite3_column_text(res, 8));
				entry->verified = sqlite3_column_int(res, 9);
				entry->owner = sqlite3_column_int(res, 10);
				ptr_vector_append(&entries, entry);
			}
			sqlite3_finalize(res);
			sqlite3_close(db);
		}
		entrycount = ptr_vector_len(&entries);

		if (entrycount > 0) {
			while (1) {
				if (redraw) {
					s_printf("\e[2J\e[1;1H");
					s_printf(get_string(270));
					s_printf(get_string(271));
					for (i = start; i < start + 22 && i < entrycount; i++) {
						struct bbs_list_entry_t *entry = ptr_vector_get(&entries, i);
						int strn = (i == selected) ? 269 : 268;
						s_printf(get_string(strn), i - start + 2, i, entry->bbsname, entry->sysopname);
					}
					s_printf("\e[%d;5H", selected - start + 2);
					redraw = 0;
				}
				c = s_getchar();
				if (tolower(c) == 'q') {
					for (i = 0; i < entrycount; i++) {
						struct bbs_list_entry_t *entry = ptr_vector_get(&entries, i);
						free(entry->bbsname);
						free(entry->sysopname);
						free(entry->software);
						free(entry->url);
						free(entry->comment);
						free(entry->location);
						free(entry);
					}
					destroy_ptr_vector(&entries);
					return;
				} else if (tolower(c) == 'a') {
					newentry = (struct bbs_list_entry_t *)malloz(sizeof(struct bbs_list_entry_t));
					if (add_bbs(newentry)) {
						ptr_vector_append(&entries, newentry);
						entrycount++;
					} else {
						free(newentry);
					}
					redraw = 1;
				} else if (tolower(c) == 'v') {
					struct bbs_list_entry_t *entry = ptr_vector_get(&entries, selected);
					entry->verified = time(NULL);
					snprintf(buffer, PATH_MAX, "%s/bbslist2.sq3", conf.bbs_path);

					rc = sqlite3_open(buffer, &db);

					if (rc != SQLITE_OK) {
						dolog("Cannot open database: %s", sqlite3_errmsg(db));
						return;
					}

					sqlite3_busy_timeout(db, 5000);
					rc = sqlite3_prepare_v2(db, vsql, -1, &res, 0);
					if (rc != SQLITE_OK) {
						sqlite3_close(db);
					} else {
						sqlite3_bind_int(res, 1, entry->verified);
						sqlite3_bind_int(res, 2, entry->id);
						sqlite3_step(res);
						sqlite3_finalize(res);
						sqlite3_close(db);
					}
				} else if (tolower(c) == 'd') {
					struct bbs_list_entry_t *entry = ptr_vector_get(&entries, selected);
					if (delete_bbs(entry->id)) {
						ptr_vector_del(&entries, selected);
						free(entry->bbsname);
						free(entry->sysopname);
						free(entry->software);
						free(entry->url);
						free(entry->comment);
						free(entry->location);
						free(entry);
						entrycount--;
						if (entrycount == 0) {
							return;
						}
						if (selected >= entrycount) {
							selected = entrycount - 1;
						}
					}
					redraw = 1;
				} else if (c == '\r') {

					struct bbs_list_entry_t *entry = ptr_vector_get(&entries, selected);
					if (entry->owner == -1) {
						ownername = strdup("System");
					} else {
						ownername = get_username(entry->owner);
					}
					s_printf("\e[2J\e[1;1H");
					s_printf(get_string(312), entry->bbsname, ownername);
					free(ownername);
					s_printf(get_string(313));
					s_printf(get_string(34), entry->sysopname);
					s_printf(get_string(311), entry->location);
					s_printf(get_string(35), entry->software);
					s_printf(get_string(304), entry->url);
					if (entry->tport == -1) {
						s_printf(get_string(306));
					} else {
						s_printf(get_string(305), entry->tport);
					}
					if (entry->sport == -1) {
						s_printf(get_string(308));
					} else {
						s_printf(get_string(307), entry->sport);
					}
					s_printf(get_string(309), entry->comment);
					localtime_r(&entry->verified, &verified);
					s_printf(get_string(314), (conf.date_style == 1 ? verified.tm_mon + 1 : verified.tm_mday), (conf.date_style == 1 ? verified.tm_mday : verified.tm_mon + 1), verified.tm_year + 1900);
					s_printf(get_string(313));
					s_printf(get_string(6));
					s_getchar();
					redraw = 1;
				} else if (c == 27) {
					c = s_getchar();
					if (c == 91) {
						c = s_getchar();
						if (c == 66) {
							// down
							if (selected + 1 >= start + 22) {
								start += 22;
								if (start >= entrycount) {
									start = entrycount - 22;
								}
								redraw = 1;
							}
							selected++;
							if (selected >= entrycount) {
								selected = entrycount - 1;
							} else {
								if (!redraw) {
									struct bbs_list_entry_t *before = ptr_vector_get(&entries, selected - 1);
									struct bbs_list_entry_t *entry = ptr_vector_get(&entries, selected);
									s_printf(get_string(268), selected - start + 1, selected - 1, before->bbsname, before->sysopname);
									s_printf(get_string(269), selected - start + 2, selected, entry->bbsname, entry->sysopname);
									s_printf("\e[%d;4H", selected - start + 2);
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
									struct bbs_list_entry_t *entry = ptr_vector_get(&entries, selected);
									struct bbs_list_entry_t *after = ptr_vector_get(&entries, selected + 1);
									s_printf(get_string(269), selected - start + 2, selected, entry->bbsname, entry->sysopname);
									s_printf(get_string(268), selected - start + 3, selected + 1, after->bbsname, after->sysopname);
									s_printf("\e[%d;4H", selected - start + 2);
								}
							}
						} else if (c == 75) {
							// END KEY
							selected = entrycount - 1;
							start = entrycount - 22;
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
							if (selected >= entrycount) {
								selected = entrycount - 1;
							}
							start = selected;
							redraw = 1;
						}
					}
				}
			}
		} else {
			// no entries
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(270));
			s_printf(get_string(271));
			s_printf(get_string(272));
			s_printf(get_string(273));

			while (1) {
				c = s_getchar();

				if (tolower(c) == 'a') {
					add_bbs(NULL);
					break;
				} else if (tolower(c) == 'q') {
					return;
				}
			}
		}
	}
}
