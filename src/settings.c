#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "bbs.h"

extern struct bbs_config conf;

void settings_menu(struct user_record *user) {
	char buffer[256];
	int dosettings = 0;
	char c;
	char *hash;
	int new_arc;
	int i;
	char *sig;

	while (!dosettings) {
		struct archiver *arc = ptr_vector_get(&conf.archivers, user->defarchiver - 1);
		struct protocol *proto = ptr_vector_get(&conf.protocols, user->defprotocol - 1);
		s_printf(get_string(149));
		s_printf(get_string(150));
		s_printf(get_string(151));
		s_printf(get_string(152), user->location);
		s_printf(get_string(205), arc->name);
		s_printf(get_string(213), proto->name);
		s_printf(get_string(215), (user->nodemsgs ? "TRUE" : "FALSE"));
		s_printf(get_string(221), (user->codepage ? "UTF-8" : "CP437"));
		switch (user->exteditor) {
			case 0:
				strlcpy(buffer, "NO", sizeof buffer);
				break;
			case 1:
				strlcpy(buffer, "YES", sizeof buffer);
				break;
			case 2:
				strlcpy(buffer, "ASK", sizeof buffer);
				break;
		}
		s_printf(get_string(222), buffer);
		s_printf(get_string(235), (user->bwavestyle ? "mo?,tu? ..." : "000-999"));
		s_printf(get_string(245));
		s_printf(get_string(246), (user->autosig ? "TRUE" : "FALSE"));
		s_printf(get_string(290), (user->dopipe ? "TRUE" : "FALSE"));
		s_printf(get_string(294), (user->qwke ? "TRUE" : "FALSE"));
		s_printf(get_string(153));
		s_printf(get_string(154));

		c = s_getc();

		switch (tolower(c)) {
			case 27: {
				c = s_getc();
				if (c == 91) {
					c = s_getc();
				}
			} break;
			case 'p': {
				s_printf(get_string(155));
				s_readpass(buffer, 16);
				hash = hash_sha256(buffer, user->salt);
				if (strcmp(hash, user->password) == 0) {
					s_printf(get_string(156));
					s_readstring(buffer, 16);
					if (strlen(buffer) >= 8) {
						free(user->password);
						free(user->salt);

						gen_salt(&user->salt);
						user->password = hash_sha256(buffer, user->salt);

						save_user(user);
						s_printf(get_string(157));
					} else {
						s_printf(get_string(158));
					}
				} else {
					s_printf(get_string(159));
				}
			} break;
			case 'l': {
				s_printf(get_string(160));
				s_readstring(buffer, 32);
				free(user->location);
				user->location = strdup(buffer);
				save_user(user);
			} break;
			case 'a': {
				s_printf(get_string(206));

				for (i = 0; i < ptr_vector_len(&conf.archivers); i++) {
					struct archiver *arc = ptr_vector_get(&conf.archivers, i);
					s_printf(get_string(207), i + 1, arc->name);
				}

				s_printf(get_string(208));
				s_readstring(buffer, 5);
				new_arc = atoi(buffer);

				if (new_arc - 1 < 0 || new_arc > ptr_vector_len(&conf.archivers)) {
					break;
				} else {
					user->defarchiver = new_arc;
					save_user(user);
				}
			} break;

			case 'o': {
				s_printf(get_string(212));

				for (i = 0; i < ptr_vector_len(&conf.protocols); i++) {
					struct protocol *proto = ptr_vector_get(&conf.protocols, i);
					s_printf(get_string(207), i + 1, proto->name);
				}

				s_printf(get_string(208));
				s_readstring(buffer, 5);
				new_arc = atoi(buffer);

				if (new_arc - 1 < 0 || new_arc > ptr_vector_len(&conf.protocols)) {
					break;
				} else {
					user->defprotocol = new_arc;
					save_user(user);
				}
			} break;
			case 'm': {
				user->nodemsgs = !user->nodemsgs;
				save_user(user);
			} break;
			case 'c': {
				user->codepage = !user->codepage;
				save_user(user);
			} break;
			case 'e': {
				user->exteditor++;
				if (user->exteditor == 3) {
					user->exteditor = 0;
				}
				save_user(user);
			} break;
			case 'b': {
				user->bwavepktno = 0;
				user->bwavestyle = !user->bwavestyle;
				save_user(user);
			} break;
			case 's': {
				// set signature
				if (user->signature != NULL) {
					free(user->signature);
				}
				sig = external_editor(user, "No-One", "No-One", NULL, 0, "No-One", "Signature Editor", 0, 1);
				if (sig != NULL) {
					user->signature = sig;
					save_user(user);
				}
			} break;
			case 't': {
				user->autosig = !user->autosig;
				save_user(user);
			} break;
			case 'i': {
				user->dopipe = !user->dopipe;
				save_user(user);
			} break;
			case 'w': {
				user->qwke = !user->qwke;
				save_user(user);
			} break;
			case 'q':
				dosettings = 1;
				break;
		}
	}
}
