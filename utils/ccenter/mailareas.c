#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void edit_mail_area_file(int confer, int area) {
    char *entrytext;
    CDKENTRY *areaFile = newCDKEntry(cdkscreen, 11, 11, "</B/32>Area Path & Filename<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(areaFile, conf.mail_conferences[confer]->mail_areas[area]->path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(areaFile, 0);

    if (areaFile->exitType == vNORMAL) {
        if (conf.mail_conferences[confer]->mail_areas[area]->path != NULL) {
            free(conf.mail_conferences[confer]->mail_areas[area]->path);
        }
        conf.mail_conferences[confer]->mail_areas[area]->path = strdup(entrytext);
    }
    destroyCDKEntry(areaFile);
}


void edit_mail_area_name(int confer, int area) {
    char *entrytext;
    CDKENTRY *areaName = newCDKEntry(cdkscreen, 11, 11, "</B/32>Area Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 64, TRUE, FALSE);
    
    setCDKEntry(areaName, conf.mail_conferences[confer]->mail_areas[area]->name, 1, 64, TRUE);

    entrytext = activateCDKEntry(areaName, 0);

    if (areaName->exitType == vNORMAL) {
        if (conf.mail_conferences[confer]->mail_areas[area]->name != NULL) {
            free(conf.mail_conferences[confer]->mail_areas[area]->name);
        }
        conf.mail_conferences[confer]->mail_areas[area]->name = strdup(entrytext);
    }
    destroyCDKEntry(areaName);
}

void edit_mail_area_qwkname(int confer, int area) {
    char *entrytext;
    CDKENTRY *areaQWKName = newCDKEntry(cdkscreen, 11, 11, "</B/32>Area QWK/Bluewave Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 8, TRUE, FALSE);
    
    setCDKEntry(areaQWKName, conf.mail_conferences[confer]->mail_areas[area]->qwkname, 1, 8, TRUE);

    entrytext = activateCDKEntry(areaQWKName, 0);

    if (areaQWKName->exitType == vNORMAL) {
        if (conf.mail_conferences[confer]->mail_areas[area]->qwkname != NULL) {
            free(conf.mail_conferences[confer]->mail_areas[area]->qwkname);
        }
        conf.mail_conferences[confer]->mail_areas[area]->qwkname = strdup(entrytext);
    }
    destroyCDKEntry(areaQWKName);
}

void edit_mail_area_type(int confer, int area) {
    char *itemList[] = {"Local",
                        "Echomail",
                        "Netmail",
                        "Newsgroup"};
    int selection;
    int doexit = 0;
    CDKSCROLL *mailAreaType = newCDKScroll(cdkscreen, 11, 11, RIGHT, 7, 30, "</B/32>Area Type<!32>", itemList, 4,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.mail_conferences[confer]->mail_areas[area]->type == TYPE_LOCAL_AREA) {
        setCDKScrollCurrent(mailAreaType, 0);
    } else if (conf.mail_conferences[confer]->mail_areas[area]->type == TYPE_ECHOMAIL_AREA) {
        setCDKScrollCurrent(mailAreaType, 1);
    }  else if (conf.mail_conferences[confer]->mail_areas[area]->type == TYPE_NETMAIL_AREA) {
        setCDKScrollCurrent(mailAreaType, 2);
    } else {
        setCDKScrollCurrent(mailAreaType, 3);
    }

    while(!doexit) {
        selection = activateCDKScroll(mailAreaType, 0);
        if (mailAreaType->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.mail_conferences[confer]->mail_areas[area]->type = TYPE_LOCAL_AREA;
                doexit = 1;
                break;
            case 1:
                conf.mail_conferences[confer]->mail_areas[area]->type = TYPE_ECHOMAIL_AREA;
                doexit = 1;
                break;
            case 2:
                conf.mail_conferences[confer]->mail_areas[area]->type = TYPE_NETMAIL_AREA;
                doexit = 1;
                break;
            case 3:
                conf.mail_conferences[confer]->mail_areas[area]->type = TYPE_NEWSGROUP_AREA;
                doexit = 1;
                break;                                
            default:
                break;
        }
    }
    destroyCDKScroll(mailAreaType);
}

void display_error() {
    char *message[] = {"A conference must have at least one area!"};
    char *buttons[] = {" OK "}; 
    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 11, 11, message, 1, buttons, 1, A_STANDOUT, FALSE, TRUE, FALSE);
    activateCDKDialog(dialog, 0);
    destroyCDKDialog(dialog);
}

void delete_mail_area(int confer, int area) {
    char *message[] = {"Do you want to Delete Related Files?"};
    char *buttons[] = {" Yes ", " No "};
    char filename[PATH_MAX];

    if (conf.mail_conferences[confer]->mail_area_count == 1) {
        display_error();
        return;
    }

    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 11, 11, message, 1, buttons, 2, A_STANDOUT, FALSE, TRUE, FALSE);

    int selection = activateCDKDialog(dialog, 0);
    int i;

    if (dialog->exitType == vESCAPE_HIT || (dialog->exitType == vNORMAL && selection == 1)) {
        // do nothing
    } else {
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
    destroyCDKDialog(dialog);

    free(conf.mail_conferences[confer]->mail_areas[area]->name);
    free(conf.mail_conferences[confer]->mail_areas[area]->path);
    free(conf.mail_conferences[confer]->mail_areas[area]->qwkname);
    free(conf.mail_conferences[confer]->mail_areas[area]);

    for (i=area;i<conf.mail_conferences[confer]->mail_area_count - 1;i++) {
        conf.mail_conferences[confer]->mail_areas[i] = conf.mail_conferences[confer]->mail_areas[i+1];
    }
    conf.mail_conferences[confer]->mail_area_count--;
    conf.mail_conferences[confer]->mail_areas = (struct mail_area **)realloc(conf.mail_conferences[confer]->mail_areas, sizeof(struct mail_area *) * conf.mail_conferences[confer]->mail_area_count);
}

void edit_mail_area(int confer, int area) {
    char *itemList[] = {"Name",
                        "Path & Filename",
                        "QWK/BlueWave Name",
                        "Read Sec. Level",
                        "Write Sec. Level",
                        "Type",
                        "Delete Mail Area"};
    
    char buffer[1024];
    int selection;

    snprintf(buffer, 1024, "</B/32>%s<!32>", conf.mail_conferences[confer]->mail_areas[area]->name);

    CDKSCROLL *editAreaList = newCDKScroll(cdkscreen, 9, 9, RIGHT, 10, 30, buffer, itemList, 7, FALSE, A_STANDOUT, TRUE, FALSE);
    
    while (1) {
        selection = activateCDKScroll(editAreaList, 0);
        if (editAreaList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_mail_area_name(confer, area);
                break;
            case 1:
                edit_mail_area_file(confer, area);
                break;
            case 2:
                edit_mail_area_qwkname(confer, area);
                break;
            case 3:
                choose_sec_level(&conf.mail_conferences[confer]->mail_areas[area]->read_sec_level, 11, 11, conf.mail_conferences[confer]->mail_areas[area]->read_sec_level);
                break;
            case 4:
                choose_sec_level(&conf.mail_conferences[confer]->mail_areas[area]->write_sec_level, 11, 11, conf.mail_conferences[confer]->mail_areas[area]->write_sec_level);            
                break;
            case 5:
                edit_mail_area_type(confer, area);
                break;
            case 6:
                delete_mail_area(confer, area);
                destroyCDKScroll(editAreaList);
                return;
            default:
                break;
        }
    }

    destroyCDKScroll(editAreaList);
}

void add_new_mail_area(int confer) {
    char areapath[PATH_MAX];
    conf.mail_conferences[confer]->mail_areas = (struct mail_area **)realloc(conf.mail_conferences[confer]->mail_areas, sizeof(struct mail_area *) * (conf.mail_conferences[confer]->mail_area_count + 1));
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count] = (struct mail_area *)malloc(sizeof(struct mail_area));
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count]->name = strdup("New Area");
    snprintf(areapath, PATH_MAX, "%s/new_area", conf.bbs_path);
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count]->path = strdup(areapath);
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count]->qwkname = strdup("NEWAREA");
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count]->read_sec_level = conf.newuserlvl;
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count]->write_sec_level = conf.newuserlvl;
    conf.mail_conferences[confer]->mail_areas[conf.mail_conferences[confer]->mail_area_count]->type = TYPE_LOCAL_AREA;
    conf.mail_conferences[confer]->mail_area_count++;
    edit_mail_area(confer, conf.mail_conferences[confer]->mail_area_count - 1);
}

void edit_mail_areas(int confer) {
    char **itemlist;
    int selection;
    int i;
    int area_count;

    while (1) {
        itemlist = (char **)malloc(sizeof(char *) * (conf.mail_conferences[confer]->mail_area_count + 1));

        itemlist[0] = strdup("Add Area");
        area_count = conf.mail_conferences[confer]->mail_area_count;
        for (i=0;i<area_count;i++) {
            itemlist[i+1] = strdup(conf.mail_conferences[confer]->mail_areas[i]->name);
        }

        CDKSCROLL *mailAreaList = newCDKScroll(cdkscreen, 7, 7, RIGHT, 12, 30, "</B/32>Mail Areas<!32>", itemlist, area_count + 1, FALSE, A_STANDOUT, TRUE, FALSE);


        selection = activateCDKScroll(mailAreaList, 0);
        if (mailAreaList->exitType == vESCAPE_HIT) {
            destroyCDKScroll(mailAreaList);
            for (i=0;i<area_count+1;i++) {
                free(itemlist[i]);
            }
            free(itemlist);
            break;
        }
        if (selection == 0) {
            // add new
            add_new_mail_area(confer);
        } else {
            // edit existing
            edit_mail_area(confer, selection - 1);
        }
        destroyCDKScroll(mailAreaList);
        for (i=0;i<area_count+1;i++) {
            free(itemlist[i]);
        }
        free(itemlist);
    }
}