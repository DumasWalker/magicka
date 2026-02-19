#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void edit_mail_conference_name(int confer) {
    char *entrytext;
    CDKENTRY *confName = newCDKEntry(cdkscreen, 7, 7, "</B/32>Conference Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 64, TRUE, FALSE);
    
    setCDKEntry(confName, conf.mail_conferences[confer]->name, 1, 64, TRUE);

    entrytext = activateCDKEntry(confName, 0);

    if (confName->exitType == vNORMAL) {
        if (conf.mail_conferences[confer]->name != NULL) {
            free(conf.mail_conferences[confer]->name);
        }
        conf.mail_conferences[confer]->name = strdup(entrytext);
    }
    destroyCDKEntry(confName);
}

void edit_mail_conference_file(int confer) {
    char *entrytext;
    CDKENTRY *confFile = newCDKEntry(cdkscreen, 7, 7, "</B/32>Conference INI Path & Filename<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(confFile, conf.mail_conferences[confer]->path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(confFile, 0);

    if (confFile->exitType == vNORMAL) {
        if (conf.mail_conferences[confer]->path != NULL) {
            free(conf.mail_conferences[confer]->path);
        }
        conf.mail_conferences[confer]->path = strdup(entrytext);
    }
    destroyCDKEntry(confFile);
}

void edit_mail_conference_networked_enable(int confer) {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *mailConfNet = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Conference is Networked<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.mail_conferences[confer]->networked == 1) {
        setCDKScrollCurrent(mailConfNet, 0);
    } else {
        setCDKScrollCurrent(mailConfNet, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(mailConfNet, 0);
        if (mailConfNet->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.mail_conferences[confer]->networked = 1;
                doexit = 1;
                break;
            case 1:
                conf.mail_conferences[confer]->networked = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(mailConfNet);
}

void edit_mail_conference_networked_type(int confer) {
    char *itemList[] = {"FTN Style"};
    int selection;
    int doexit = 0;
    CDKSCROLL *mailConfNet = newCDKScroll(cdkscreen, 9, 9, RIGHT, 4, 30, "</B/32>Network Type<!32>", itemList,1,FALSE, A_STANDOUT, TRUE, FALSE);

    while(!doexit) {
        selection = activateCDKScroll(mailConfNet, 0);
        if (mailConfNet->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.mail_conferences[confer]->nettype = NETWORK_FIDO;
                doexit = 1;
                break;        
            default:
                break;
        }
    }
    destroyCDKScroll(mailConfNet);
}

void edit_mail_conference_networked_address(int confer) {
    char *entrytext;
    char buffer[128];
    struct fido_addr *new_addr;
    CDKENTRY *mailConfAddr = newCDKEntry(cdkscreen, 9, 9, "</B/32>Network Address<!32>", NULL, A_NORMAL, ' ', vMIXED, 32, 1, 32, TRUE, FALSE);
    
    if (conf.mail_conferences[confer]->fidoaddr != NULL) {
 
        snprintf(buffer, 128, "%d:%d/%d.%d", conf.mail_conferences[confer]->fidoaddr->zone, conf.mail_conferences[confer]->fidoaddr->net, conf.mail_conferences[confer]->fidoaddr->node, conf.mail_conferences[confer]->fidoaddr->point);

        setCDKEntry(mailConfAddr, buffer, 1, 32, TRUE);
    }
    entrytext = activateCDKEntry(mailConfAddr, 0);

    if (mailConfAddr->exitType == vNORMAL) {
        new_addr = parse_fido_addr(entrytext);
        if (new_addr != NULL) {
            if (conf.mail_conferences[confer]->fidoaddr != NULL) {
                free(conf.mail_conferences[confer]->fidoaddr);
            }
            conf.mail_conferences[confer]->fidoaddr = new_addr;
        }
    }
    destroyCDKEntry(mailConfAddr);
}

void edit_mail_conference_networked(int confer) {
    char *itemList[] = {"Networked",
                        "Network Type",
                        "Network Address"
                        };
    int selection;
    CDKSCROLL *editConfNetList = newCDKScroll(cdkscreen, 7, 7, RIGHT, 6, 30, "</B/32>Network Options<!32>", itemList, 3, FALSE, A_STANDOUT, TRUE, FALSE);
    while (1) {
        selection = activateCDKScroll(editConfNetList, 0);
        if (editConfNetList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_mail_conference_networked_enable(confer);
                break;
            case 1:
                edit_mail_conference_networked_type(confer);
                break;
            case 2:
                edit_mail_conference_networked_address(confer);
                break;
            default:
                break;
        } 
    }            
}

void edit_mail_conference_tagline(int confer) {
    char *entrytext;
    CDKENTRY *confTagLine = newCDKEntry(cdkscreen, 9, 9, "</B/32>Conference Tagline<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 80, TRUE, FALSE);
    
    setCDKEntry(confTagLine, conf.mail_conferences[confer]->tagline, 1, 80, TRUE);

    entrytext = activateCDKEntry(confTagLine, 0);

    if (confTagLine->exitType == vNORMAL) {
        if (conf.mail_conferences[confer]->tagline != NULL) {
            free(conf.mail_conferences[confer]->tagline);
        }
        conf.mail_conferences[confer]->tagline = strdup(entrytext);
    }
    destroyCDKEntry(confTagLine);
}

void edit_mail_conference_realnames(int confer) {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *mailConfRN = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Conference is Networked<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.mail_conferences[confer]->realnames == 1) {
        setCDKScrollCurrent(mailConfRN, 0);
    } else {
        setCDKScrollCurrent(mailConfRN, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(mailConfRN, 0);
        if (mailConfRN->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.mail_conferences[confer]->realnames = 1;
                doexit = 1;
                break;
            case 1:
                conf.mail_conferences[confer]->realnames = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(mailConfRN);
}

void display_conf_error() {
    char *message[] = {"Must have at least one Conference!"};
    char *buttons[] = {" OK "}; 
    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 7, 7, message, 1, buttons, 1, A_STANDOUT, FALSE, TRUE, FALSE);
    activateCDKDialog(dialog, 0);
    destroyCDKDialog(dialog);
}

void delete_mail_conference(int confer) {
    char *message[] = {"Do you want to Delete Related Files?"};
    char *buttons[] = {" Yes ", " No "};
    char filename[PATH_MAX];
    int area;

    if (conf.mail_conference_count == 1) {
        display_conf_error();
        return;
    }

    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 7, 7, message, 1, buttons, 2, A_STANDOUT, FALSE, TRUE, FALSE);

    int selection = activateCDKDialog(dialog, 0);
    int i;

    if (dialog->exitType == vESCAPE_HIT || (dialog->exitType == vNORMAL && selection == 1)) {
        // do nothing
    } else {
        for (area=0;area<conf.mail_conferences[confer]->mail_area_count;area++) {
            snprintf(filename, PATH_MAX, "%s.jdt", conf.mail_conferences[confer]->mail_areas[area]->path);
            unlink(filename);
            snprintf(filename, PATH_MAX, "%s.jdx", conf.mail_conferences[confer]->mail_areas[area]->path);
            unlink(filename);
            snprintf(filename, PATH_MAX, "%s.jhr", conf.mail_conferences[confer]->mail_areas[area]->path);
            unlink(filename);
            snprintf(filename, PATH_MAX, "%s.jlr", conf.mail_conferences[confer]->mail_areas[area]->path);
            unlink(filename);
            snprintf(filename, PATH_MAX, "%s.cmhw", conf.mail_conferences[confer]->mail_areas[area]->path);
            unlink(filename);
        }
        unlink(conf.mail_conferences[confer]->path);
    }
    destroyCDKDialog(dialog);

    for (area=0;area<conf.mail_conferences[confer]->mail_area_count;area++) {
        free(conf.mail_conferences[confer]->mail_areas[area]->name);
        free(conf.mail_conferences[confer]->mail_areas[area]->path);
        free(conf.mail_conferences[confer]->mail_areas[area]->qwkname);
        free(conf.mail_conferences[confer]->mail_areas[area]);
    }

    free(conf.mail_conferences[confer]->mail_areas);
    free(conf.mail_conferences[confer]->name);
    free(conf.mail_conferences[confer]->path);
    if (conf.mail_conferences[confer]->tagline) {
        free(conf.mail_conferences[confer]->tagline);
    }
    if (conf.mail_conferences[confer]->fidoaddr) {
        free(conf.mail_conferences[confer]->fidoaddr);
    }
    for (i=confer;i<conf.mail_conference_count - 1;i++) {
        conf.mail_conferences[i]= conf.mail_conferences[i+1];
    }
    conf.mail_conference_count--;
    conf.mail_conferences = (struct mail_conference **)realloc(conf.mail_conferences, sizeof(struct mail_conference *) * conf.mail_conference_count);
}

void edit_mail_conference(int confer) {
    char *itemList[] = {"Name",
                        "INI Path & Filename",
                        "Visible Sec. Level",
                        "Networked",
                        "Tag Line",
                        "Use Real Names",
                        "Edit Areas",
                        "Delete Conference"};
    
    char buffer[1024];
    int selection;

    snprintf(buffer, 1024, "</B/32>%s<!32>", conf.mail_conferences[confer]->name);

    CDKSCROLL *editConfList = newCDKScroll(cdkscreen, 5, 5, RIGHT, 10, 30, buffer, itemList, 7, FALSE, A_STANDOUT, TRUE, FALSE);
    
    while (1) {
        selection = activateCDKScroll(editConfList, 0);
        if (editConfList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_mail_conference_name(confer);
                break;
            case 1:
                edit_mail_conference_file(confer);
                break;
            case 2:
                choose_sec_level(&conf.mail_conferences[confer]->sec_level, 7, 7, conf.mail_conferences[confer]->sec_level);
                break;
            case 3:
                edit_mail_conference_networked(confer);
                break;
            case 4:
                edit_mail_conference_tagline(confer);
                break;
            case 5:
                edit_mail_conference_realnames(confer);
                break;
            case 6:
                edit_mail_areas(confer);
                break;
            case 7:
                delete_mail_conference(confer);
                destroyCDKScroll(editConfList);
                return;
            default:
                break;
        }
    }

    destroyCDKScroll(editConfList);
}

void add_new_mail_conference() {
    char areapath[PATH_MAX];
    conf.mail_conferences = (struct mail_conference **)realloc(conf.mail_conferences, sizeof(struct mail_conference *) * (conf.mail_conference_count + 1));
    conf.mail_conferences[conf.mail_conference_count] = (struct mail_conference *)malloc(sizeof(struct mail_conference));    
    conf.mail_conferences[conf.mail_conference_count]->mail_areas = (struct mail_area **)malloc(sizeof(struct mail_area *));
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0] = (struct mail_area *)malloc(sizeof(struct mail_area));
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0]->name = strdup("New Area");
    snprintf(areapath, PATH_MAX, "%s/new_area", conf.bbs_path);
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0]->path = strdup(areapath);
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0]->qwkname = strdup("NEWAREA");
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0]->read_sec_level = conf.newuserlvl;
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0]->write_sec_level = conf.newuserlvl;
    conf.mail_conferences[conf.mail_conference_count]->mail_areas[0]->type = TYPE_LOCAL_AREA;
    conf.mail_conferences[conf.mail_conference_count]->mail_area_count = 1;
    
    conf.mail_conferences[conf.mail_conference_count]->name = strdup("New Conference");
    snprintf(areapath, PATH_MAX, "%s/new_conf.ini", conf.config_path);
    conf.mail_conferences[conf.mail_conference_count]->path = strdup(areapath);
    conf.mail_conferences[conf.mail_conference_count]->tagline = strdup(conf.default_tagline);
    conf.mail_conferences[conf.mail_conference_count]->networked = 0;
    conf.mail_conferences[conf.mail_conference_count]->nettype = NETWORK_FIDO;
    conf.mail_conferences[conf.mail_conference_count]->realnames = 0;
    conf.mail_conferences[conf.mail_conference_count]->sec_level = conf.newuserlvl;
    conf.mail_conferences[conf.mail_conference_count]->fidoaddr = (struct fido_addr *)malloc(sizeof(struct fido_addr));
    memcpy(conf.mail_conferences[conf.mail_conference_count]->fidoaddr, conf.main_aka, sizeof(struct fido_addr));
    conf.mail_conferences[conf.mail_conference_count]->wwivnode = 0;

    conf.mail_conference_count ++;

    edit_mail_conference(conf.mail_conference_count-1);
}

void mail_conferences() {
    char **itemlist;
    int selection;
    int i;
    int confcount;

    while (1) {
        itemlist = (char **)malloc(sizeof(char *) * (conf.mail_conference_count + 1));
        confcount = conf.mail_conference_count;
        itemlist[0] = strdup("Add Conference");

        for (i=0;i<confcount;i++) {
            itemlist[i+1] = strdup(conf.mail_conferences[i]->name);
        }

        CDKSCROLL *mailConfList = newCDKScroll(cdkscreen, 3, 3, RIGHT, 12, 30, "</B/32>Mail Conferences<!32>", itemlist, confcount + 1, FALSE, A_STANDOUT, TRUE, FALSE);


        selection = activateCDKScroll(mailConfList, 0);
        if (mailConfList->exitType == vESCAPE_HIT) {
            destroyCDKScroll(mailConfList);
            for (i=0;i<confcount+1;i++) {
                free(itemlist[i]);
            }
            free(itemlist);
            break;
        }
        if (selection == 0) {
            // add new
            add_new_mail_conference();        
        } else {
            // edit existing
            edit_mail_conference(selection - 1);
        }
        destroyCDKScroll(mailConfList);
        for (i=0;i<confcount+1;i++) {
            free(itemlist[i]);
        }
        free(itemlist);
    }
}