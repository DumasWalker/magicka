#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void set_bbs_path(void) {
    char *entrytext;
    char *old_path = strdup(conf.bbs_path);
    char *new_path;

    CDKENTRY *bbsPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>BBS Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(bbsPath, conf.bbs_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(bbsPath, 0);

    if (bbsPath->exitType == vNORMAL) {
        if (conf.bbs_path != NULL) {
            free(conf.bbs_path);
        }
        conf.bbs_path = strdup(entrytext);
    }
    destroyCDKEntry(bbsPath);
    char *message[] = {"Do you want to apply this path to all other paths?"};
    char *buttons[] = {" Yes ", " No "};
    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 7, 7, message, 1, buttons, 2, A_STANDOUT, FALSE, TRUE, FALSE);

    int selection = activateCDKDialog(dialog, 0);

    if (dialog->exitType == vESCAPE_HIT || (dialog->exitType == vNORMAL && selection == 1)) {
        // do nothing
    } else {
        if (strncmp(conf.www_path, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.www_path[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.www_path[strlen(old_path)]);
            free(conf.www_path);
            conf.www_path = new_path;
        }
        if (strncmp(conf.config_path, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.config_path[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.config_path[strlen(old_path)]);
            free(conf.config_path);
            conf.config_path = new_path;
        }
        if (strncmp(conf.string_file, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.string_file[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.string_file[strlen(old_path)]);
            free(conf.string_file);
            conf.string_file = new_path;
        }
        if (strncmp(conf.pid_file, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.pid_file[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.pid_file[strlen(old_path)]);
            free(conf.pid_file);
            conf.pid_file = new_path;
        }
        if (strncmp(conf.ansi_path, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.ansi_path[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.ansi_path[strlen(old_path)]);
            free(conf.ansi_path);
            conf.ansi_path = new_path;
        }
        if (strncmp(conf.log_path, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.log_path[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.log_path[strlen(old_path)]);
            free(conf.log_path);
            conf.log_path = new_path;
        }
        if (strncmp(conf.script_path, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.script_path[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.script_path[strlen(old_path)]);
            free(conf.script_path);
            conf.script_path = new_path;
        }
        if (strncmp(conf.echomail_sem, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.echomail_sem[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.echomail_sem[strlen(old_path)]);
            free(conf.echomail_sem);
            conf.echomail_sem = new_path;
        }
        if (strncmp(conf.netmail_sem, old_path, strlen(old_path)) == 0) {
            new_path = (char *)malloc(strlen(conf.bbs_path) + strlen(&conf.netmail_sem[strlen(old_path)]) + 1);
            sprintf(new_path, "%s%s", conf.bbs_path, &conf.netmail_sem[strlen(old_path)]);
            free(conf.netmail_sem);
            conf.netmail_sem = new_path;
        }                                                   
    }
    free(old_path);
    destroyCDKDialog(dialog);
}

void set_config_path(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>Config Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.config_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.config_path != NULL) {
            free(conf.config_path);
        }
        conf.config_path = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_ansi_path(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>ANSI Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.ansi_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.ansi_path != NULL) {
            free(conf.ansi_path);
        }
        conf.ansi_path = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_script_path(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>Script Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.script_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.script_path != NULL) {
            free(conf.script_path);
        }
        conf.script_path = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_log_path(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>Log Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.log_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.log_path != NULL) {
            free(conf.log_path);
        }
        conf.log_path = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_string_file(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>String File<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.string_file, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.string_file != NULL) {
            free(conf.string_file);
        }
        conf.string_file = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_pid_file(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>PID File<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.pid_file, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.pid_file != NULL) {
            free(conf.pid_file);
        }
        conf.pid_file = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_echomail_sem(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>Echomail Semaphore<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.echomail_sem, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.echomail_sem != NULL) {
            free(conf.echomail_sem);
        }
        conf.echomail_sem = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void set_netmail_sem(void) {
    char *entrytext;
    CDKENTRY *configPath = newCDKEntry(cdkscreen, 5, 5, "</B/32>Netmail Semaphore<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(configPath, conf.netmail_sem, 1, 1024, TRUE);

    entrytext = activateCDKEntry(configPath, 0);

    if (configPath->exitType == vNORMAL) {
        if (conf.netmail_sem != NULL) {
            free(conf.netmail_sem);
        }
        conf.netmail_sem = strdup(entrytext);
    }
    destroyCDKEntry(configPath);
}

void system_paths() {
    char *itemList[] = {"BBS Path",
                        "Config Path",
                        "ANSI Path",
                        "Script Path",
                        "Log Path",
                        "String File",
                        "PID File",
                        "Echomail Semaphore",
                        "Netmail Semaphore"};

    int selection;

    CDKSCROLL *sysPathItemList = newCDKScroll(cdkscreen, 3, 3, RIGHT, 12, 30, "</B/32>System Paths<!32>", itemList, 9, FALSE, A_STANDOUT, TRUE, FALSE);

    while (1) {
        selection = activateCDKScroll(sysPathItemList, 0);
        if (sysPathItemList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                set_bbs_path();
                break;
            case 1:
                set_config_path();
                break;
            case 2:
                set_ansi_path();
                break;
            case 3:
                set_script_path();
                break;
            case 4:
                set_log_path();
                break;
            case 5:
                set_string_file();
                break;
            case 6:
                set_pid_file();
                break;
            case 7:
                set_echomail_sem();
                break;
            case 8:
                set_netmail_sem();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(sysPathItemList);
}