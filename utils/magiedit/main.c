#if WIN32
#   define _MSC_VER 1
#	define _CRT_SECURE_NO_WARNINGS
#   include <Windows.h>
#else
#
#endif

#include <OpenDoor.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>

#ifndef DRAFT_PATH
#define DRAFT_PATH ""
#endif

#ifndef ANSI_PATH
#define ANSI_PATH ""
#endif

char **quote_lines;
int quote_line_count;

char *msgfrom;
char *msgto;
char *msgsubj;
char *msgarea;
int msgpriv;

char *draft_filename = NULL;

char *load_draft() {
	DIR *dirp;
	struct dirent *dent;
	char draft_path[PATH_MAX];
	char **filenames;
	int filename_count = 0;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	int i;
	tODInputEvent ch;
	
	snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s", od_control_get()->user_name);
	
	dirp = opendir(draft_path);
	
	if (!dirp) {
		od_clr_scr();
		od_printf("`bright red`You have no drafts!\r\n`white`");
		od_printf("Press a key...");
		
		od_get_key(TRUE);
		return NULL;
	}
	
	while ((dent = readdir(dirp)) != NULL) {
		if (strlen(dent->d_name) > 6 && strcmp(&dent->d_name[strlen(dent->d_name) - 6], ".draft") == 0) {
			if (filename_count == 0) {
				filenames = (char **)malloc(sizeof(char *));
			} else {
				filenames = (char **)realloc(filenames, sizeof(char *) * (filename_count + 1));
			}
			
			filenames[filename_count] = strndup(dent->d_name, strlen(dent->d_name) - 6);
			
			filename_count++;
		}
	}
	closedir(dirp);
	
	if (filename_count == 0) {
		od_clr_scr();
		od_printf("`bright red`You have no drafts!\r\n`white`");
		od_printf("Press a key...");
		od_get_key(TRUE);
		return NULL;		
	}
	
	
	while (1) {
		if (redraw) {
			od_set_color(D_GREY, D_BLACK);
			od_clr_scr();
			
			od_set_color(D_BLACK, D_CYAN);
			od_set_cursor(1, 1);
			od_printf("Your Drafts:");
			od_clr_line();
			od_set_cursor(24, 1);
			od_printf("Up/Down Select, Enter confirm, D to Delete, Esc to cancel");
			od_clr_line();
			
			for (i = start;i < start + 22 && i < filename_count; i++) {
				if (i == selected) {
					od_set_cursor(i - start + 2, 1);
					od_set_color(D_BLACK, D_MAGENTA);
					od_printf("%s", filenames[i]);
					od_clr_line();
				} else {
					od_set_cursor(i - start + 2, 1);
					od_set_color(D_GREY, D_BLACK);
					od_printf("%s", filenames[i]);
					od_clr_line();					 
				}
			}
			redraw = 0;
		}
		
		od_get_input(&ch, OD_NO_TIMEOUT, GETIN_RAWCTRL);
        if (ch.EventType == EVENT_EXTENDED_KEY) {
			if (ch.chKeyPress == OD_KEY_UP) {
				selected--;
                if (selected < 0) {
					selected = 0;
                }
                if (selected < start) {
					start = start - 22;
                    if (start < 0) {
						start = 0;
                    }
                    redraw = 1;
                }
                                            
                if (!redraw) {
					od_set_cursor(selected - start + 2, 1);
                    od_set_color(D_BLACK, D_MAGENTA);
                    od_printf("%s", filenames[selected]);
                    od_clr_line();
                    
                    if (filename_count > selected + 1) {             
						od_set_cursor(selected + 1 - start + 2, 1);
						od_set_color(D_GREY, D_BLACK);
						od_printf("%s", filenames[selected + 1]);
						od_clr_line();     
					}
					od_set_cursor(selected - start + 2, 1);
                }                                   
            }
            
            if (ch.chKeyPress == OD_KEY_DOWN) {
				selected++;
				if (selected >= filename_count) {
					selected = filename_count - 1;
                }

                if (selected >= start + 22) {
					start = start + 22;
                    if (start + 22 >= filename_count) {
						start = filename_count - 22;
                    }
                    redraw = 1;
                }
                if (!redraw) {
					od_set_cursor(selected - start + 2, 1);
                    od_set_color(D_BLACK, D_MAGENTA);
                    od_printf("%s", filenames[selected]);
                    od_clr_line();
                    if (selected - 1 >= 0) {
						od_set_cursor(selected - 1 - start + 2, 1);
						od_set_color(D_GREY, D_BLACK);
						od_printf("%s", filenames[selected - 1]);
						od_clr_line();                                         
					}
					od_set_cursor(selected - start + 2, 1);
                }                                   
			}                                
        } else {
			if (ch.chKeyPress == 27) {
				// escape
				for (i=0;i<filename_count;i++) {
					free(filenames[i]);
				}
				free(filenames);
				
				return NULL;
			} else if (ch.chKeyPress == 13) {
				draft_filename = strdup(filenames[selected]);
				
				for (i=0;i<filename_count;i++) {
					free(filenames[i]);
				}
				free(filenames);				
				
				return draft_filename;
			} else if (ch.chKeyPress == 'd') {
				snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s/%s.draft", od_control_get()->user_name, filenames[selected]);
				unlink(draft_path);
				
				free(filenames[selected]);
				
				for (i=selected;i<filename_count - 1; i++) {
					filenames[i] = filenames[i+1];
				}
				
				filename_count--;
				if (filename_count == 0) {
					free(filenames);
					return NULL;
				} else {
					filenames = (char **)realloc(filenames, sizeof(char *) * filename_count);
				}
				redraw = 1;
				selected--;
				
				if (selected < 0) {
					selected = 0;
				}
			}
		}
	}
}

void delete_draft(char *filename) {
	char draft_path[PATH_MAX];
	
	snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s/%s.draft", od_control_get()->user_name, filename);
	
	unlink(draft_path);
}

int check_draft_filename(char *filename) {
	struct stat s;
	char draft_path[PATH_MAX];
	int i;
	
	for (i=0;i<strlen(filename);i++) {
		if (!isalnum(filename[i])) {
			filename[i] = '_';
		}
	}
	
	if (stat("drafts", &s) != 0) {
		mkdir("drafts", 0700);
	}
	
	snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s", od_control_get()->user_name);
	
	if (stat(draft_path, &s) != 0) {
		mkdir(draft_path, 0700);
	}
	
	snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s/%s.draft", od_control_get()->user_name, filename);
	
	if (stat(draft_path, &s) != 0) {
		return 1;
	}
	return 0;
}

char *message_editor() {
    char **body_lines;
    int body_line_count;
    int position_x;
    int position_y;
    int done;
    char line[81];
    char line_cpy[81];
    int top_of_screen = 0;
    int i, j;
    char *return_body;
    int body_len;
    tODInputEvent ch;
    int q_done;
    char q_marker;
    int q_start;
    int q_position;
    int *q_lines;
    int q_line_count;
    int q_unquote;
    int z;
    int redraw;
    int old_top_of_screen = 0;
    int stage = 0;
    int qq_start;
    int draft_ext;
    char draft_path[PATH_MAX];
    FILE *fptr;
    char d_draft;
    
    position_x = 0;
    position_y = 0;
    body_line_count = 0;
    done = 0;
    q_position = 0;
    q_start = 0;
	
    memset(line, 0, 81);
    memset(line_cpy, 0, 81);

    while (!done) {
        od_clr_scr();
        od_set_cursor(1, 1);
        od_send_file(ANSI_PATH "magiedit.ans");
        od_set_color(D_GREY, D_BLACK);
        od_set_cursor(2, 13);
        od_printf("%-26.26s", msgto);
        od_set_cursor(3, 13);
        od_printf("%-26.26s", msgsubj);
        od_set_cursor(2, 52);
        od_printf("%-26.26s", msgarea);
        od_set_cursor(5, 1);
        while (1) {
            od_get_input(&ch, OD_NO_TIMEOUT, GETIN_RAWCTRL);
            if (ch.EventType == EVENT_EXTENDED_KEY) {
                if (ch.chKeyPress == OD_KEY_UP) {
                    if (position_y > 0) {
                        strcpy(line_cpy, body_lines[position_y - 1]);
                        free(body_lines[position_y - 1]);
                        body_lines[position_y - 1] = strdup(line);
                        strcpy(line, line_cpy);
                        position_y--;

                        if (position_x >= strlen(line)) {
                            position_x = strlen(line);
                        }

                        if (position_y < top_of_screen) {
                            top_of_screen--;

                        }
                        if (old_top_of_screen != top_of_screen) {
                            od_set_cursor(5, 1);

                            for (i=top_of_screen;i<position_y;i++) {
                                od_set_cursor(i - top_of_screen + 5, 1);
                                od_printf("%s", body_lines[i]);
                                od_clr_line();
                            }
                            od_set_cursor(i - top_of_screen + 5, 1);
                            od_printf("%s", line);
                            od_clr_line();
                            for (i=position_y;i<body_line_count && i < top_of_screen + 17;i++) {
                                od_set_cursor(i - top_of_screen + 6, 1);
                                od_printf("%s", body_lines[i]);
                                od_clr_line();
                            }

                        }
                        old_top_of_screen = top_of_screen;

                        od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
                    }
                } else if (ch.chKeyPress == OD_KEY_DOWN) {
                    if (position_y < body_line_count) {
                        strcpy(line_cpy, body_lines[position_y]);
                        free(body_lines[position_y]);
                        body_lines[position_y] = strdup(line);
                        strcpy(line, line_cpy);
                        position_y++;

                        if (position_x >= strlen(line)) {
                            position_x = strlen(line);
                        }

                        if (position_y > top_of_screen + 17) {
                            top_of_screen++;

                        }
                        if (old_top_of_screen != top_of_screen) {
                            od_set_cursor(3, 1);

                            for (i=top_of_screen;i<position_y;i++) {
                                od_set_cursor(i - top_of_screen + 5, 1);
                                od_printf("%s", body_lines[i]);
                                od_clr_line();
                            }
                            od_set_cursor(i - top_of_screen + 5, 1);
                            od_printf("%s", line);
                            od_clr_line();
                            for (i=position_y;i<body_line_count && i < top_of_screen + 17;i++) {
                                od_set_cursor(i - top_of_screen + 6, 1);
                                od_printf("%s", body_lines[i]);
                                od_clr_line();
                            }
                        }
                        old_top_of_screen = top_of_screen;
                        od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
                    }
                } else if (ch.chKeyPress == OD_KEY_LEFT) {
                    if (position_x > 0) {
                        position_x--;
                        od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
                    }

                } else if (ch.chKeyPress == OD_KEY_RIGHT) {
                    if (position_x < strlen(line)) {
                        position_x++;
                        od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
                    }
                } else if (ch.chKeyPress == OD_KEY_END) {
					position_x = strlen(line);
					od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
				} else if (ch.chKeyPress == OD_KEY_HOME) {
					position_x = 0;
					od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
				} else if (ch.chKeyPress == OD_KEY_F9) {
					// save as draft
					if (draft_filename == NULL) {
						draft_filename = strdup(msgsubj);
						if (!check_draft_filename(draft_filename)) {
							draft_ext = 0;
							do {
								draft_ext++;
								free(draft_filename);
								
								draft_filename = (char *)malloc(sizeof(char) * (strlen(msgsubj) + 4));
								
								snprintf(draft_filename, strlen(msgsubj) + 4, "%s_%d", msgsubj, draft_ext);
							} while (!check_draft_filename(draft_filename) && draft_ext < 999);
						}
						if (draft_ext == 1000) {
							free(draft_filename);
							draft_filename = NULL;
						}
					}
					
					if (draft_filename != NULL) {
						// save
						// save message
						body_len = 0;
						for (i=0;i<position_y;i++) {
							body_len = body_len + strlen(body_lines[i]) + 2;
						}
						body_len = body_len + strlen(line) + 2;
						for (i=position_y;i<body_line_count;i++) {
							body_len = body_len + strlen(body_lines[i]) + 2;
						}

						body_len++;

						return_body = (char *)malloc(body_len);
						memset(return_body, 0, body_len);

						for (i=0;i<position_y;i++) {
							strcat(return_body, body_lines[i]);
							strcat(return_body, "\r\n");
						}
						strcat(return_body, line);
						strcat(return_body, "\r\n");
							
						for (i=position_y;i<body_line_count;i++) {
							strcat(return_body, body_lines[i]);
							strcat(return_body, "\r\n");
						}

						// write 	
						snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s/%s.draft", od_control_get()->user_name, draft_filename);
					    fptr = fopen(draft_path, "w");

						if (!fptr) {
							od_printf("`bright red`Unable to save draft!\r\n`white`");
						} else {
							fwrite(return_body, 1, strlen(return_body), fptr);

							fclose(fptr);						
							od_printf("`bright green`Draft saved as \"%s\".`white`\r\n", draft_filename);
						}
						free(return_body);
					} else {
						od_printf("`bright red`Unable to save draft!\r\n`white`");
					}
						
					od_printf("Press a key...");
					od_get_key(TRUE);
						
					od_set_color(D_GREY, D_BLACK);
                    // restore screen
                    od_clr_scr();
                    od_set_cursor(1, 1);
                    od_send_file(ANSI_PATH "magiedit.ans");
                    od_set_color(D_GREY, D_BLACK);
                    od_set_cursor(2, 13);
                    od_printf("%-26.26s", msgto);
                    od_set_cursor(3, 13);
                    od_printf("%-26.26s", msgsubj);
                    od_set_cursor(2, 52);
                    od_printf("%-26.26s", msgarea);
                    od_set_cursor(5, 1);

                    if (position_y - top_of_screen > 17) {
                        top_of_screen = position_y - 17;
                    }

                    for (i=top_of_screen;i<top_of_screen + 17;i++) {
                        od_set_cursor(i - top_of_screen + 5, 1);
                        if (i < body_line_count) {
                            od_printf("%s", body_lines[i]);
                        }
                        od_clr_line();
                    }
                    position_x = 0;
                    memset(line, 0, 81);
                    od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
				} else if (ch.chKeyPress == OD_KEY_F10) {
					// load draft
					if (load_draft() != NULL) {
						snprintf(draft_path, PATH_MAX, DRAFT_PATH "drafts/%s/%s.draft", od_control_get()->user_name, draft_filename);
					    fptr = fopen(draft_path, "r");
					    if (!fptr) {
							// error loading draft
						} else {
							// free body lines;
							if (body_line_count > 0) {
								for (i=0;i<body_line_count;i++) {
									free(body_lines[i]);
								}
							
								free(body_lines);
								body_line_count = 0;
							}
							position_x = 0;
							position_y = 0;
							
							fgets(line, 80, fptr);
							while (!feof(fptr)) {
								if (body_line_count == 0) {
									body_lines = (char **)malloc(sizeof(char *));
								} else {
									body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
								}
								
								body_lines[body_line_count] = (char *)malloc(strlen(line));
								snprintf(body_lines[body_line_count], strlen(line) - 1, "%s", line);
								body_line_count++;
								position_y++;
								fgets(line, 80, fptr);
							}
							fclose(fptr);
						}
					    
					    
					}
					
					od_set_color(D_GREY, D_BLACK);
                    // restore screen
                    od_clr_scr();
                    od_set_cursor(1, 1);
                    od_send_file(ANSI_PATH "magiedit.ans");
                    od_set_color(D_GREY, D_BLACK);
                    od_set_cursor(2, 13);
                    od_printf("%-26.26s", msgto);
                    od_set_cursor(3, 13);
                    od_printf("%-26.26s", msgsubj);
                    od_set_cursor(2, 52);
                    od_printf("%-26.26s", msgarea);
                    od_set_cursor(5, 1);

                    if (position_y - top_of_screen > 17) {
                        top_of_screen = position_y - 17;
                    }

                    for (i=top_of_screen;i<top_of_screen + 17;i++) {
                        od_set_cursor(i - top_of_screen + 5, 1);
                        if (i < body_line_count) {
                            od_printf("%s", body_lines[i]);
                        }
                        od_clr_line();
                    }
                    position_x = 0;
                    memset(line, 0, 81);
                    od_set_cursor(position_y - top_of_screen + 5, position_x + 1);					
				}
            } else if (ch.EventType == EVENT_CHARACTER) {
               if (ch.chKeyPress == '\r' || (strlen(line) >= 73 && ch.chKeyPress > 31 && ch.chKeyPress != 127)) {
                    if (strlen(line) >= 73 && ch.chKeyPress != '\r') {
                        if (position_x == strlen(line)) {
                            strncat(line, &ch.chKeyPress, 1);
                            z = 1;
                         } else {
                            strncpy(line_cpy, line, position_x);
                            line_cpy[position_x] = '\0';
                            strncat(line_cpy, &ch.chKeyPress, 1);
                            strcat(line_cpy, &line[position_x]);
                            memset(line, 0, 81);
                            strcpy(line, line_cpy);
                            memset(line_cpy, 0, 81);
                            z = 0;
                        }

                        for (i=strlen(line)-1;i>0;i--) {
                            if (line[i] == ' ') {
                                line[i] = '\0';
                                strcpy(line_cpy, &line[i+1]);
                                if (body_line_count == 0) {
                                    body_lines = (char **)malloc(sizeof(char *));
                                } else {
                                    body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
                                }
                                if (z == 1) {
                                    for (j=body_line_count;j>position_y;j--) {
                                        body_lines[j] = body_lines[j-1];
                                    }
                                    body_line_count++;
                                    body_lines[j] = strdup(line);

                                    position_y++;
                                    if (position_y - top_of_screen > 17) {
                                        top_of_screen++;
                                    }
                                    strcpy(line, line_cpy);
                                    memset(line_cpy, 0, 81);
                                    position_x = strlen(line);
                                } else {
                                    if (strlen(body_lines[position_y]) + strlen(line_cpy) + 1 <= 73) {
                                        strcat(line_cpy, " ");
                                        strcat(line_cpy, body_lines[position_y]);
                                        free(body_lines[position_y]);
                                        body_lines[position_y] = strdup(line_cpy);
                                        memset(line_cpy, 0, 81);
                                        position_x++;
                                    } else {
                                        for (j=body_line_count;j>position_y;j--) {
                                            body_lines[j] = body_lines[j-1];
                                        }
                                        body_line_count++;
                                        body_lines[j] = strdup(line_cpy);

                                        memset(line_cpy, 0, 81);
                                        position_x++;
                                    }
                                }
                                od_set_cursor(position_y - top_of_screen + 5 - 1, 1);
                                od_printf("%s", body_lines[position_y - 1]);
                                od_clr_line();
                                od_set_cursor(position_y - top_of_screen + 5, 1);
                                od_printf("%s", line);
                                od_clr_line();
                                break;
                            }
                        }
                        if (i==0) {
                            position_x++;
                            if (body_line_count == 0) {
                                body_lines = (char **)malloc(sizeof(char *));
                            } else {
                                body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
                            }

                            for (i=body_line_count;i>position_y;i--) {
                                body_lines[i] = body_lines[i-1];
                            }
                            body_line_count++;
                            body_lines[i] = strdup(line);
                            if (z == 1) {
                                position_y++;
                                if (position_y - top_of_screen > 17) {
                                    top_of_screen++;
                                }
                                position_x = 0;
                            }
                            memset(line, 0, 81);
                        }
                                              
                    } else {
                         if (position_x < strlen(line)) {
                            // insert line
                            if (body_line_count == 0) {
                                body_lines = (char **)malloc(sizeof(char *));
                            } else {
                                body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
                            }

                            for (i=body_line_count;i>position_y;i--) {
                                body_lines[i] = body_lines[i-1];
                            }

                            body_line_count++;
                            body_lines[i] = (char *)malloc(sizeof(char) * (position_x + 1));
                            strncpy(body_lines[i], line, position_x);
                            body_lines[i][position_x] = '\0';
                            strcpy(line_cpy, &line[position_x]);
                            memset(line, 0, 81);
                            strcpy(line, line_cpy);
                            memset(line_cpy, 0, 81);

                            position_y++;
                            if (position_y - top_of_screen > 17) {
                                top_of_screen++;
                            }
                            position_x = 0;
                            od_clr_line();
                        } else {
                            if (body_line_count == 0) {
                                body_lines = (char **)malloc(sizeof(char *));
                            } else {
                                body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
                            }

                            for (i=body_line_count;i>position_y;i--) {
                                body_lines[i] = body_lines[i-1];
                            }
                            body_line_count++;
                            body_lines[i] = strdup(line);

                            position_y++;
                            if (position_y - top_of_screen > 17) {
                                top_of_screen++;
                            }
                            position_x = 0;
                            memset(line, 0, 81);
                        }
                    }


                    if (old_top_of_screen != top_of_screen) {
                        od_set_cursor(5, 1);

                        for (i=top_of_screen;i<position_y;i++) {
                            od_set_cursor(i - top_of_screen + 5, 1);
                            od_printf("%s", body_lines[i]);
                            od_clr_line();
                        }
                        od_set_cursor(i - top_of_screen + 5, 1);
                        od_printf("%s", line);
                        od_clr_line();
                    } 
                    old_top_of_screen = top_of_screen;
                       
                    if (position_x > 0) {
                        od_set_cursor(position_y - top_of_screen + 5, position_x);
                        od_printf("%s", &line[position_x-1]);
                        od_clr_line();
                            
                    } else {
                        od_set_cursor(position_y - top_of_screen + 5, 1);
                        od_printf("%s", line);
                        od_clr_line();
                    }
                    for (i=position_y;i<body_line_count && i - top_of_screen < 17;i++) {
                        od_set_cursor(i - top_of_screen + 6, 1);
                        od_printf("%s", body_lines[i]);
                        od_clr_line();
                    }   
                    od_set_cursor(position_y - top_of_screen + 5, position_x + 1);                            
                } else {
                    if (ch.chKeyPress == '\b' || ch.chKeyPress == 127) {
                        if (position_x == 0 && position_y > 0) {
                            // TODO
                            if (strlen(line) == 0) {
								// delete line move cursor to end of previous line
								if (position_y < body_line_count) {
									strcpy(line, body_lines[position_y - 1]);
									free(body_lines[position_y - 1]);
									for (i=position_y - 1;i<body_line_count-1;i++) {
										body_lines[i] = body_lines[i+1];
									}
									body_line_count--;
									if (body_line_count == 0) {
										free(body_lines);
									} else {
										body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count));
									}
									
									position_y--;
									position_x = strlen(line);
								} else {
									memcpy(line, body_lines[body_line_count -1], 81);
									free(body_lines[body_line_count - 1]);
									body_line_count--;
									if (body_line_count == 0) {
										free(body_lines);
									} else {
										body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count));
									}
									position_y--;
									position_x = strlen(line);
								}								
								
							} else {
								// check if current line fits 
								if (strlen(body_lines[position_y - 1]) + strlen(line) < 73) {
									// it fits, move it up to the previous line
									
									j = strlen(body_lines[position_y - 1]);
									
									strcpy(line_cpy, body_lines[position_y - 1]);
									strcat(line_cpy, line);
									strcpy(line, line_cpy);
									
									free(body_lines[position_y - 1]);
									for (i=position_y - 1;i<body_line_count-1;i++) {
										body_lines[i] = body_lines[i+1];
									}
									body_line_count--;
									if (body_line_count == 0) {
										free(body_lines);
									} else {
										body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count));
									}
									
									position_y--;
									position_x = j;									
									
								} else {
									// it doesn't fit move cursor to end of previous line
									strcpy(line_cpy, body_lines[position_y - 1]);
									free(body_lines[position_y - 1]);
									body_lines[position_y - 1] = strdup(line);
									strcpy(line, line_cpy);
									position_y--;
									position_x = strlen(line);
								}
							}

							if (position_y < top_of_screen) {
								top_of_screen--;
							}
							
							od_set_cursor(position_y - top_of_screen + 5, 1);
							od_printf("%s", line);
							od_clr_line();
							
							i = position_y + 1;
							
							if (position_y + 1 <= body_line_count) {
								for (; i<= body_line_count && i < top_of_screen + 17;i++) {
									od_set_cursor(i - top_of_screen + 5, 1);
									od_printf("%s", body_lines[i-1]);
									od_clr_line();
								}
							}
							for (;i< top_of_screen + 17;i++) {
								od_set_cursor(i - top_of_screen + 5, 1);
								od_clr_line();
							}							
                        } else if (position_x > 0) {
                            if (position_x >= strlen(line)) {
                                strncpy(line_cpy, line, strlen(line) - 1);
                                line_cpy[strlen(line) - 1] = '\0';
                                memset(line, 0, 81);
                                strcpy(line, line_cpy);
                                memset(line_cpy, 0, 81);
                                position_x--;
                            } else {
                                strncpy(line_cpy, line, position_x -1);
                                line_cpy[position_x - 1] = '\0';
                                strcat(line_cpy, &line[position_x]);
                                strcpy(line, line_cpy);
                                memset(line_cpy, 0, 81);
                                position_x--;

                            }
                        }
                    } else if (ch.chKeyPress == 17) {
                        if (quote_line_count > 0) {
                            // Quote
                            od_clr_scr();
                            od_set_cursor(1, 1);
                            od_send_file(ANSI_PATH "magiquote.ans");
                            od_set_color(D_GREY, D_BLACK);
                            od_set_cursor(2, 13);
                            od_printf("%-26.26s", msgto);
                            od_set_cursor(3, 13);
                            od_printf("%-26.26s", msgsubj);
                            od_set_cursor(2, 52);
                            od_printf("%-26.26s", msgarea);
                            od_set_cursor(5, 1);
                            
                            
                            q_line_count = 0;
                            q_done = 0;
                            redraw = 1;
                            qq_start = 0;

                            if (strlen(line) > 0) {

                                if (body_line_count == 0) {
                                    body_lines = (char **)malloc(sizeof(char *));
                                } else {
                                    body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
                                }

                                for (i=body_line_count;i>position_y;i--) {
                                    body_lines[i] = body_lines[i-1];
                                }
                                body_line_count++;
                                body_lines[i] = strdup(line);

                                position_y++;
                            }
                            // do quoting...
                            while (!q_done) {
                                if (redraw) {
                                    if (q_line_count - 9 < 0) {
                                        qq_start = 0;
                                    } else {
                                        qq_start = q_line_count - 9;
                                    }
                                    od_set_color(D_GREY, D_BLACK);
                                    for (i=qq_start;i<q_line_count;i++) {    
                                        od_set_cursor(5 + (i - qq_start), 1);
                                        od_printf("%s", quote_lines[q_lines[i]]);
                                        od_clr_line();
                                    }

                                    for (i=q_start;i<q_start + 7 && i<quote_line_count;i++) {
                                        od_set_cursor(16 + (i - q_start), 1);
                                        if (i == q_position) {
                                            od_set_color(D_BLACK, D_MAGENTA);
                                        } else {
                                            od_set_color(D_GREY, D_BLACK);
                                        }
                                        od_printf("%s", quote_lines[i]);
                                        od_clr_line();
                                    }
                                }
                                od_get_input(&ch, OD_NO_TIMEOUT, GETIN_RAWCTRL);
                                if (ch.EventType == EVENT_EXTENDED_KEY) {
                                    if (ch.chKeyPress == OD_KEY_UP) {
                                        q_position--;
                                        if (q_position < 0) {
                                            q_position = 0;
                                        }
                                        if (q_position < q_start) {
                                            q_start = q_start - 7;
                                            if (q_start < 0) {
                                                q_start = 0;
                                            }
                                            redraw = 1;
                                        }
                                            
                                        if (!redraw) {
                                            od_set_cursor(q_position - q_start + 16, 1);
                                            od_set_color(D_BLACK, D_MAGENTA);
                                            od_printf("%s", quote_lines[q_position]);
                                            od_clr_line();
                                            if (q_position + 1 < quote_line_count) {
												od_set_cursor(q_position + 1 - q_start + 16, 1);
												od_set_color(D_BLACK, D_MAGENTA);
												od_printf("%s", quote_lines[q_position + 1]);
												od_clr_line();     
											}
                                        }                                   
                                    }
                                    if (ch.chKeyPress == OD_KEY_DOWN) {
                                        q_position++;
                                        if (q_position >= quote_line_count) {
                                            q_position = quote_line_count - 1;
                                        }

                                        if (q_position >= q_start + 7) {
                                            q_start = q_start + 7;
                                            if (q_start + 7 >= quote_line_count) {
                                                q_start = quote_line_count - 7;
                                            }
                                            redraw = 1;
                                        }
                                        if (!redraw) {
                                            od_set_cursor(q_position - q_start + 16, 1);
                                            od_set_color(D_BLACK, D_MAGENTA);
                                            od_printf("%s", quote_lines[q_position]);
                                            od_clr_line();
                                            if (q_position - 1 >= 0) {
												od_set_cursor(q_position - 1 - q_start + 16, 1);
												od_set_color(D_BLACK, D_MAGENTA);
												od_printf("%s", quote_lines[q_position - 1]);
												od_clr_line();                                            
											}
                                        }                                   
                                    }                                
                                } else {
                                    if (ch.chKeyPress == 17) {
                                        // do quote
                                        for (i=0;i<q_line_count;i++) {
                                            if (body_line_count == 0) {
                                                body_lines = (char **)malloc(sizeof(char *));
                                            } else {
                                                body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count + 1));
                                            }

                                            for (j=body_line_count;j>position_y;j--) {
                                                body_lines[j] = body_lines[j-1];
                                            }

                                            body_lines[j] = strdup(quote_lines[q_lines[i]]);
                                            position_y++;
                                            body_line_count++;
                                        }
                                        if (q_line_count) {
                                            free(q_lines);
                                        }
                                        position_x = 0;
                                        q_done = 1;                                    
                                    } else if (ch.chKeyPress == 27) {
                                        if (q_line_count) {
                                            free(q_lines);
                                        }
                                        q_done = 1;
                                    } else if (ch.chKeyPress == 13) {
                                        // add line to quote body
                                        if (q_line_count == 0) {
                                            q_lines = (int *)malloc(sizeof(int *));
                                        } else {
                                            q_lines = (int *)realloc(q_lines, sizeof(int *) * (q_line_count + 1));
                                        }

                                        q_lines[q_line_count] = q_position;
                                        q_line_count++;

                                        q_position++;
                                        if (q_position >= quote_line_count) {
                                            q_position = quote_line_count - 1;
                                        }
                                        if (q_position >= q_start + 7) {
                                            q_start = q_start + 7;
                                            if (q_start + 7 >= quote_line_count) {
                                                q_start = quote_line_count - 7;
                                            }
                                        }                                      
                                        redraw = 1;                        
                                    }
                                }
                            }
                            od_set_color(D_GREY, D_BLACK);
                            // restore screen
                            od_clr_scr();
                            od_set_cursor(1, 1);
                            od_send_file(ANSI_PATH "magiedit.ans");
                            od_set_color(D_GREY, D_BLACK);
                            od_set_cursor(2, 13);
                            od_printf("%-26.26s", msgto);
                            od_set_cursor(3, 13);
                            od_printf("%-26.26s", msgsubj);
                            od_set_cursor(2, 52);
                            od_printf("%-26.26s", msgarea);
                            od_set_cursor(5, 1);

                            

                            if (position_y - top_of_screen > 17) {
                                top_of_screen = position_y - 17;
                            }

                            for (i=top_of_screen;i<top_of_screen + 17;i++) {
                                od_set_cursor(i - top_of_screen + 5, 1);
                                if (i < body_line_count) {
                                    od_printf("%s", body_lines[i]);
                                }
                                od_clr_line();
                            }
                            position_x = 0;
                            memset(line, 0, 81);
                            od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
                        }
                    } else if (ch.chKeyPress == 24) {
                        // abort
                        if (body_line_count > 0) {
                            for (i=0;i<body_line_count;i++) {
                                free(body_lines[i]);
                            }
                            free(body_lines);
                        }
                        return NULL; 
					} else if (ch.chKeyPress == 25) {
						// ctrl-y delete current line
						if (position_y < body_line_count) {
							strcpy(line, body_lines[position_y]);
							free(body_lines[position_y]);
							for (i=position_y;i<body_line_count-1;i++) {
								body_lines[i] = body_lines[i+1];
							}
							body_line_count--;
							if (body_line_count == 0) {
								free(body_lines);
							} else {
								body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count));
							}
						} else {
							if (body_line_count > 0) {
								memcpy(line, body_lines[body_line_count -1], 81);
								free(body_lines[body_line_count - 1]);
								body_line_count--;
								if (body_line_count == 0) {
									free(body_lines);
								} else {
									body_lines = (char **)realloc(body_lines, sizeof(char *) * (body_line_count));
								}
								position_y--;
							} else {
								memset(line, 0, 81);
							}
						}
						
						if (position_y < top_of_screen) {
							top_of_screen--;
						}
						
						// refresh screen;
						position_x = 0;
						if (position_y <= body_line_count) {
							for (i=position_y; i< body_line_count && i < top_of_screen + 18;i++) {
								od_set_cursor(i - top_of_screen + 5, 1);
								od_printf("%s", body_lines[i]);
								od_clr_line();
							}
						}
						for (;i< top_of_screen + 18;i++) {
							od_set_cursor(i - top_of_screen + 5, 1);
							od_clr_line();
						}

                    } else if (ch.chKeyPress == 26) {
                        // save
                        // save message
                        body_len = 0;
                        for (i=0;i<position_y;i++) {
                            body_len = body_len + strlen(body_lines[i]) + 2;
                        }
                        body_len = body_len + strlen(line) + 2;
                        for (i=position_y;i<body_line_count;i++) {
                            body_len = body_len + strlen(body_lines[i]) + 2;
                        }

                        body_len++;

                        return_body = (char *)malloc(body_len);
                        memset(return_body, 0, body_len);

                        for (i=0;i<position_y;i++) {
                            strcat(return_body, body_lines[i]);
                            strcat(return_body, "\r\n");
                        }
                        strcat(return_body, line);
                        strcat(return_body, "\r\n");
                            
                        for (i=position_y;i<body_line_count;i++) {
                            strcat(return_body, body_lines[i]);
                            strcat(return_body, "\r\n");
                        }


                        if (body_line_count > 0) {
                            for (i=0;i<body_line_count;i++) {
                                free(body_lines[i]);
                            }
                            free(body_lines);
                        }

						od_clr_scr();

						if (draft_filename != NULL) {
							od_printf("`bright white`Delete draft \"%s\"? (Y/N) ", draft_filename);
							d_draft = od_get_answer("YyNn");
							
							if (tolower(d_draft) == 'y') {
								delete_draft(draft_filename);
							}
						}

                        return return_body;     
                    } else if (ch.chKeyPress != '\n' && ch.chKeyPress != 0x1b) {
                        if (position_x >= strlen(line)) {
                            strncat(line, &ch.chKeyPress, 1);
                        } else {
                            strncpy(line_cpy, line, position_x);
                            line_cpy[position_x] = '\0';
                            strncat(line_cpy, &ch.chKeyPress, 1);
                            strcat(line_cpy, &line[position_x]);
                            memset(line, 0, 81);
                            strcpy(line, line_cpy);
                            memset(line_cpy, 0, 81);
                        }
                        position_x++;
                    }

                    if (position_x > 0) {
                        od_set_cursor(position_y - top_of_screen + 5, position_x);
                        od_printf("%s", &line[position_x-1]);
                        od_clr_line();       
                    } else {
                        od_set_cursor(position_y - top_of_screen + 5, 1);
                        od_printf("%s", line);
                        od_clr_line();
                    }
                    od_set_cursor(position_y - top_of_screen + 5, position_x + 1);
                }
            }
        }
    }
    return NULL;
}

#if _MSC_VER
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdLine, int nCmdShow)
{
#else
int main(int argc, char **argv)
{
#endif
    char *msgtmp;
    char *msginf;
    char path_sep;
    char *msgpath;
    int noquote;
    char buffer[256];
    FILE *fptr;
    char *body;
    char *unwrapped_quote;
    int unwrapped_quote_len;
    int i, j;
    int last_space;
    int start_line;
    msgpath = NULL;
    char *ptr;
    
#if _MSC_VER
    int j;

	for (i=0;i<strlen(lpszCmdLine);i++) {
        if (strncmp(&lpszCmdLine[i], "-MSGTMP ", 8) == 0 || strncmp(&lpszCmdLine[i], "/MSGTMP ", 8) == 0) {
            msgpath = strdup(&lpszCmdLine[i + 8]);
            for (j=0;j<strlen(msgtmp);j++) {
                if (msgpath[j] == ' ') {
                    msgpath[j] = '\0';
                    break;
                }
            }
        }
	}
    od_parse_cmd_line(lpszCmdLine);
    path_sep = '\';'
#else
	for (i=0;i<argc;i++) {
		if (strcmp(argv[i], "-MSGTMP") == 0 || strcmp(argv[i], "/MSGTMP") == 0) {

			msgpath = strdup(argv[i+1]);
		}
	}
    od_parse_cmd_line(argc, argv);
    path_sep = '/';
#endif

    if (msgpath == NULL) {
        fprintf(stderr, "No MSGTMP switch specified!\n");
        exit(0);
    }

    od_init();
    
    od_control_get()->od_page_pausing = FALSE;

    msgtmp = (char *)malloc(strlen(msgpath) + 8);
    if (!msgtmp) {
        od_printf("Out of Memory!\r\n");
        od_exit(-1, FALSE);
    }

    msginf = (char *)malloc(strlen(msgpath) + 8);
    if (!msginf) {
        od_printf("Out of Memory!\r\n");
        od_exit(-1, FALSE);
    }

    sprintf(msgtmp, "%s%cMSGTMP", msgpath, path_sep);
    sprintf(msginf, "%s%cMSGINF", msgpath, path_sep);


    fptr = fopen(msginf, "r");

    if (!fptr) {
        sprintf(msginf, "%s%cmsginf", msgpath, path_sep);
        fptr = fopen(msginf, "r");
        if (!fptr) {
            od_printf("Unable to open MSGINF!\r\n");
            od_exit(-1, FALSE);
            return -1;
        }
    }

    fgets(buffer, 256, fptr);
    for (i=strlen(buffer) - 1; i > 0; i--) {
        if (buffer[i] != '\r' && buffer[i] != '\n') {
            break;
        } else {
            buffer[i] = '\0';
        }
    }

    msgfrom = strdup(buffer);

    fgets(buffer, 256, fptr);
    for (i=strlen(buffer) - 1; i > 0; i--) {
        if (buffer[i] != '\r' && buffer[i] != '\n') {
            break;
        } else {
            buffer[i] = '\0';
        }
    }

    msgto = strdup(buffer);

    fgets(buffer, 256, fptr);
    for (i=strlen(buffer) - 1; i > 0; i--) {
        if (buffer[i] != '\r' && buffer[i] != '\n') {
            break;
        } else {
            buffer[i] = '\0';
        }
    }

    msgsubj = strdup(buffer);

    fgets(buffer, 256, fptr); // msg no, we don't care

    fgets(buffer, 256, fptr);
    for (i=strlen(buffer) - 1; i > 0; i--) {
        if (buffer[i] != '\r' && buffer[i] != '\n') {
            break;
        } else {
            buffer[i] = '\0';
        }
    }

    msgarea = strdup(buffer);

    fgets(buffer, 256, fptr);
    for (i=strlen(buffer) - 1; i > 0; i--) {
        if (buffer[i] != '\r' && buffer[i] != '\n') {
            break;
        } else {
            buffer[i] = '\0';
        }
    }

    if (strcasecmp(buffer, "YES") == 0) {
        msgpriv = 1;
    } else {
        msgpriv = 0;
    }


    fclose(fptr);

    noquote = 0;

    fptr = fopen(msgtmp, "r");

    if (!fptr) {
        sprintf(msgtmp, "%s%cmsgtmp", msgpath, path_sep);
        fptr = fopen(msgtmp, "r");
        if (!fptr) {
            sprintf(msgtmp, "%s%cMSGTMP", msgpath, path_sep);
            noquote = 1;
        }
    }
    quote_line_count = 0;

    int lshort = 0;

    if (!noquote) {
		fgets(buffer, 79, fptr);
		while (!feof(fptr)) {
            if (buffer[0] == '\n' || (buffer[0] == '\r' && lshort == 1)) {
                lshort = 0;
                fgets(buffer, 79, fptr);
                continue;
            }
		    if (quote_line_count == 0) {
				quote_lines = (char **)malloc(sizeof(char *));
			} else {
				quote_lines = (char **)realloc(quote_lines, sizeof(char *) * (quote_line_count + 1));
			}	    

            ptr = strrchr(buffer, '\r');
            if (ptr != NULL) {
                *ptr = '\0';
                lshort = 0;
            } else {
                lshort = 1;
            }

            if (buffer[0] == '\0') {
                buffer[0] = ' ';
                buffer[1] = '\0';
            }
            
            quote_lines[quote_line_count] = strdup(buffer);


            quote_line_count++;

			memset(buffer, 0, 256);
			fgets(buffer, 79, fptr);
        }
        fclose(fptr);
        unlink(msgtmp);
    }

    body = message_editor();

    if (body == NULL) {
        od_printf("Message Aborted!\r\n");
        od_exit(0, FALSE);
        return 0;
    }

    for (i=0;i<quote_line_count;i++) {
        free(quote_lines[i]);
    }

    free(quote_lines);

    fptr = fopen(msgtmp, "w");

    if (!fptr) {
        od_printf("Error saving message!\r\n");
        od_exit(-1, FALSE);
        return -1;
    }

    fwrite(body, 1, strlen(body), fptr);

    fclose(fptr);

    od_exit(0, FALSE);
    return 0;
}
