#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void edit_file_sub_name(int fdir, int area) {
    char *entrytext;
    CDKENTRY *areaName = newCDKEntry(cdkscreen, 11, 11, "</B/32>File Sub Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 64, TRUE, FALSE);
    
    setCDKEntry(areaName, conf.file_directories[fdir]->file_subs[area]->name, 1, 64, TRUE);

    entrytext = activateCDKEntry(areaName, 0);

    if (areaName->exitType == vNORMAL) {
        if (conf.file_directories[fdir]->file_subs[area]->name != NULL) {
            free(conf.file_directories[fdir]->file_subs[area]->name );
        }
        conf.file_directories[fdir]->file_subs[area]->name  = strdup(entrytext);
    }
    destroyCDKEntry(areaName);
}

void edit_file_sub_dbase(int fdir, int area) {
    char *entrytext;
    CDKENTRY *areaFile = newCDKEntry(cdkscreen, 11, 11, "</B/32>Database Path & Filename<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(areaFile, conf.file_directories[fdir]->file_subs[area]->database, 1, 1024, TRUE);

    entrytext = activateCDKEntry(areaFile, 0);

    if (areaFile->exitType == vNORMAL) {
        if (conf.file_directories[fdir]->file_subs[area]->database != NULL) {
            free(conf.file_directories[fdir]->file_subs[area]->database);
        }
        conf.file_directories[fdir]->file_subs[area]->database = strdup(entrytext);
    }
    destroyCDKEntry(areaFile);
}


void edit_file_sub_uploadp(int fdir, int area) {
    char *entrytext;
    CDKENTRY *areaFile = newCDKEntry(cdkscreen, 11, 11, "</B/32>Upload Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(areaFile, conf.file_directories[fdir]->file_subs[area]->upload_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(areaFile, 0);

    if (areaFile->exitType == vNORMAL) {
        if (conf.file_directories[fdir]->file_subs[area]->upload_path != NULL) {
            free(conf.file_directories[fdir]->file_subs[area]->upload_path);
        }
        conf.file_directories[fdir]->file_subs[area]->upload_path = strdup(entrytext);
    }
    destroyCDKEntry(areaFile);
}

void display_fsub_error() {
    char *message[] = {"A directory must have at least one sub directory!"};
    char *buttons[] = {" OK "}; 
    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 11, 11, message, 1, buttons, 1, A_STANDOUT, FALSE, TRUE, FALSE);
    activateCDKDialog(dialog, 0);
    destroyCDKDialog(dialog);
}

void delete_file_sub(int fdir, int area) {
    char *message[] = {"Do you want to Delete Related Files?"};
    char *buttons[] = {" Yes ", " No "};
    char filename[PATH_MAX];

    if (conf.file_directories[fdir]->file_sub_count == 1) {
        display_fsub_error();
        return;
    }

    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 11, 11, message, 1, buttons, 2, A_STANDOUT, FALSE, TRUE, FALSE);

    int selection = activateCDKDialog(dialog, 0);
    int i;

    if (dialog->exitType == vESCAPE_HIT || (dialog->exitType == vNORMAL && selection == 1)) {
        // do nothing
    } else {
        snprintf(filename, PATH_MAX, "%s.sq3", conf.file_directories[fdir]->file_subs[area]->database);
        unlink(filename);
    }
    destroyCDKDialog(dialog);

    free(conf.file_directories[fdir]->file_subs[area]->name);
    free(conf.file_directories[fdir]->file_subs[area]->database);
    free(conf.file_directories[fdir]->file_subs[area]->upload_path);
    free(conf.file_directories[fdir]->file_subs[area]);

    for (i=area;i<conf.file_directories[fdir]->file_sub_count - 1;i++) {
        conf.file_directories[fdir]->file_subs[i] = conf.file_directories[fdir]->file_subs[i+1];
    }
    conf.file_directories[fdir]->file_sub_count--;
    conf.file_directories[fdir]->file_subs = (struct file_sub **)realloc(conf.file_directories[fdir]->file_subs, sizeof(struct file_sub *) * conf.file_directories[fdir]->file_sub_count);
}

void edit_file_sub(int fdir, int area) {
    char *itemList[] = {"Name",
                        "Database Dir & Path",
                        "Upload Path",
                        "Upload Sec. Level",
                        "Download Sec. Level",
                        "Delete File Sub Dir"};
    
    char buffer[1024];
    int selection;

    snprintf(buffer, 1024, "</B/32>%s<!32>", conf.file_directories[fdir]->file_subs[area]->name);

    CDKSCROLL *editSubList = newCDKScroll(cdkscreen, 9, 9, RIGHT, 9, 30, buffer, itemList, 6, FALSE, A_STANDOUT, TRUE, FALSE);
    
    while (1) {
        selection = activateCDKScroll(editSubList, 0);
        if (editSubList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_file_sub_name(fdir, area);
                break;
            case 1:
                edit_file_sub_dbase(fdir, area);
                break;
            case 2:
                edit_file_sub_uploadp(fdir, area);
                break;
            case 3:
                choose_sec_level(&conf.file_directories[fdir]->file_subs[area]->upload_sec_level, 11, 11, conf.file_directories[fdir]->file_subs[area]->upload_sec_level);
                break;
            case 4:
                choose_sec_level(&conf.file_directories[fdir]->file_subs[area]->download_sec_level, 11, 11, conf.file_directories[fdir]->file_subs[area]->download_sec_level);
                break;
            case 5:
                delete_file_sub(fdir, area);
                destroyCDKScroll(editSubList);
                return;
            default:
                break;
        }
    }

    destroyCDKScroll(editSubList);
}

void add_new_file_sub(int fdir) {
    char areapath[PATH_MAX];
    conf.file_directories[fdir]->file_subs = (struct file_sub **)realloc(conf.file_directories[fdir]->file_subs, sizeof(struct file_sub *) * (conf.file_directories[fdir]->file_sub_count + 1));
    conf.file_directories[fdir]->file_subs[conf.file_directories[fdir]->file_sub_count] = (struct file_sub *)malloc(sizeof(struct file_sub));
    conf.file_directories[fdir]->file_subs[conf.file_directories[fdir]->file_sub_count]->name = strdup("New Sub Directory");
    snprintf(areapath, PATH_MAX, "%s/new_area", conf.bbs_path);
    conf.file_directories[fdir]->file_subs[conf.file_directories[fdir]->file_sub_count]->database = strdup(areapath);
    conf.file_directories[fdir]->file_subs[conf.file_directories[fdir]->file_sub_count]->upload_path = strdup(conf.bbs_path);
    conf.file_directories[fdir]->file_subs[conf.file_directories[fdir]->file_sub_count]->upload_sec_level = conf.newuserlvl;
    conf.file_directories[fdir]->file_subs[conf.file_directories[fdir]->file_sub_count]->download_sec_level = conf.newuserlvl;
    conf.file_directories[fdir]->file_sub_count++;
    edit_file_sub(fdir, conf.file_directories[fdir]->file_sub_count - 1);
}

void edit_file_subdirs(int fdir) {
    char **itemlist;
    int selection;
    int i;
    int area_count;

    while (1) {
        itemlist = (char **)malloc(sizeof(char *) * (conf.file_directories[fdir]->file_sub_count + 1));

        itemlist[0] = strdup("Add Sub Directory");
        area_count = conf.file_directories[fdir]->file_sub_count;
        for (i=0;i<area_count;i++) {
            itemlist[i+1] = strdup(conf.file_directories[fdir]->file_subs[i]->name);
        }

        CDKSCROLL *fileSubList = newCDKScroll(cdkscreen, 7, 7, RIGHT, 12, 30, "</B/32>File Sub Dirs<!32>", itemlist, area_count + 1, FALSE, A_STANDOUT, TRUE, FALSE);


        selection = activateCDKScroll(fileSubList, 0);
        if (fileSubList->exitType == vESCAPE_HIT) {
            destroyCDKScroll(fileSubList);
            for (i=0;i<area_count+1;i++) {
                free(itemlist[i]);
            }
            free(itemlist);
            break;
        }
        if (selection == 0) {
            // add new
            add_new_file_sub(fdir);
        } else {
            // edit existing
            edit_file_sub(fdir, selection - 1);
        }
        destroyCDKScroll(fileSubList);
        for (i=0;i<area_count+1;i++) {
            free(itemlist[i]);
        }
        free(itemlist);
    }
}