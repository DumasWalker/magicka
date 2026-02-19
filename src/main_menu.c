#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include "bbs.h"
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"

extern struct bbs_config conf;
extern struct user_record *gUser;
extern int mynode;

void display_bulletins() {
	int i;
	char buffer[PATH_MAX];
	struct stat s;
	i = 0;

	snprintf(buffer, sizeof buffer, "%s/bulletin%d.ans", conf.ansi_path, i);
	while (stat(buffer, &s) == 0) {
		s_printf("\e[2J\e[1;1H");
		s_displayansi_pause(buffer, 1);
		s_printf(get_string(185));
		s_getc();
		s_printf("\r\n");
		i++;
		snprintf(buffer, sizeof buffer, "%s/bulletin%d.ans", conf.ansi_path, i);
	}
}

void active_nodes() {
	int i;
	struct stat s;
	char buffer[PATH_MAX];
	FILE *fptr;

	s_printf("\e[2J\e[1;1H");
	s_printf(get_string(317));
	s_printf(get_string(318));
	for (i = 0; i < conf.nodes; i++) {
		snprintf(buffer, PATH_MAX, "%s/nodeinuse.%d", conf.bbs_path, i + 1);
		if (stat(buffer, &s) == 0) {
			fptr = fopen(buffer, "r");
			if (fptr) {
				fgets(buffer, PATH_MAX, fptr);
				fclose(fptr);
				chomp(buffer);
				s_printf(get_string(216), i + 1, buffer);
			}
		} else {
			s_printf(get_string(316), i+1);
		}
	}
	s_printf(get_string(318));
}

void send_node_msg() {
	char buffer[PATH_MAX];
	char msg[257];
	int nodetomsg = 0;
	struct stat s;
	FILE *fptr;


	active_nodes();
	s_printf(get_string(217));
	s_readstring(buffer, 4);
	nodetomsg = atoi(buffer);

	if (nodetomsg < 1 || nodetomsg > conf.nodes) {
		s_printf(get_string(218));
		return;
	}
	s_printf(get_string(219));

	s_readstring(msg, 256);

	snprintf(buffer, PATH_MAX, "%s/node%d", conf.bbs_path, nodetomsg);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}
	snprintf(buffer, PATH_MAX, "%s/node%d/nodemsg.txt", conf.bbs_path, nodetomsg);

	fptr = fopen(buffer, "a");
	if (fptr) {
		fprintf(fptr, get_string(220), gUser->loginname, mynode, msg);
		fclose(fptr);
	}
}

void display_textfiles() {
	int i;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;

	if (ptr_vector_len(&conf.text_files) == 0) {
		s_printf("\e[2J\e[1;1H");
		s_printf(get_string(148));
		s_printf(get_string(185));
		s_getc();
		s_printf("\r\n");
		return;
	}

	while (1) {
		if (redraw) {
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(143));
			s_printf(get_string(144));
			for (size_t i = start; i < start + 22 && i < ptr_vector_len(&conf.text_files); i++) {
				struct text_file *file = ptr_vector_get(&conf.text_files, i);
				s_printf(get_string(i == selected ? 249 : 250), i - start + 2, i, file->name);
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
						if (start >= ptr_vector_len(&conf.text_files)) {
							start = ptr_vector_len(&conf.text_files) - 22;
						}
						redraw = 1;
					}
					selected++;
					if (selected >= ptr_vector_len(&conf.text_files)) {
						selected = ptr_vector_len(&conf.text_files) - 1;
					} else {
						if (!redraw) {
							struct text_file *prev_file = ptr_vector_get(&conf.text_files, selected - 1);
							struct text_file *file = ptr_vector_get(&conf.text_files, selected);
							assert(prev_file != NULL);
							assert(file != NULL);
							s_printf(get_string(250), selected - start + 1, selected - 1, prev_file->name);
							s_printf(get_string(249), selected - start + 2, selected, file->name);
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
							struct text_file *file = ptr_vector_get(&conf.text_files, selected);
							struct text_file *next_file = ptr_vector_get(&conf.text_files, selected + 1);
							s_printf(get_string(249), selected - start + 2, selected, file->name);
							s_printf(get_string(250), selected - start + 3, selected + 1, next_file->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 75) {
					// END KEY
					selected = ptr_vector_len(&conf.text_files) - 1;
					start = selected - 21;
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
					if (selected >= ptr_vector_len(&conf.text_files)) {
						selected = ptr_vector_len(&conf.text_files) - 1;
					}
					start = selected;
					redraw = 1;
				}
			}
		} else if (c == 13) {
			struct text_file *file = ptr_vector_get(&conf.text_files, selected);
			assert(file != NULL);
			s_printf("\e[2J\e[1;1H");
			s_displayansi_p(file->path);
			s_printf(get_string(185));
			s_getc();
			s_printf("\r\n");
			redraw = 1;
		}
	}
}
