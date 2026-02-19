#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void edit_file_directory_name(int fdir) {
    char *entrytext;
    CDKENTRY *dirName = newCDKEntry(cdkscreen, 7, 7, "</B/32>File Directory Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 64, TRUE, FALSE);
    
    setCDKEntry(dirName, conf.file_directories[fdir]->name, 1, 64, TRUE);

    entrytext = activateCDKEntry(dirName, 0);

    if (dirName->exitType == vNORMAL) {
        if (conf.file_directories[fdir]->name != NULL) {
            free(conf.file_directories[fdir]->name);
        }
        conf.file_directories[fdir]->name = strdup(entrytext);
    }
    destroyCDKEntry(dirName);
}

void edit_file_directory_file(int fdir) {
    char *entrytext;
    CDKENTRY *dirFile = newCDKEntry(cdkscreen, 7, 7, "</B/32>File Dir. INI Path & Filename<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(dirFile, conf.file_directories[fdir]->path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(dirFile, 0);

    if (dirFile->exitType == vNORMAL) {
        if (conf.file_directories[fdir]->path != NULL) {
            free(conf.file_directories[fdir]->path);
        }
        conf.file_directories[fdir]->path = strdup(entrytext);
    }
    destroyCDKEntry(dirFile);
}

void display_fdir_error() {
    char *message[] = {"Must have at least one File Directory!"};
    char *buttons[] = {" OK "}; 
    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 7, 7, message, 1, buttons, 1, A_STANDOUT, FALSE, TRUE, FALSE);
    activateCDKDialog(dialog, 0);
    destroyCDKDialog(dialog);
}


void delete_file_directory(int fdir) {
    char *message[] = {"Do you want to Delete Related Files?"};
    char *buttons[] = {" Yes ", " No "};
    char filename[PATH_MAX];
    int area;

    if (conf.file_directory_count == 1) {
        display_fdir_error();
        return;
    }

    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 7, 7, message, 1, buttons, 2, A_STANDOUT, FALSE, TRUE, FALSE);

    int selection = activateCDKDialog(dialog, 0);
    int i;

    if (dialog->exitType == vESCAPE_HIT || (dialog->exitType == vNORMAL && selection == 1)) {
        // do nothing
    } else {
        for (area=0;area<conf.file_directories[fdir]->file_sub_count;area++) {
            snprintf(filename, PATH_MAX, "%s.sq3", conf.file_directories[fdir]->file_subs[area]->database);
            unlink(filename);
        }
        unlink(conf.file_directories[fdir]->path);
    }
    destroyCDKDialog(dialog);

    for (area=0;area<conf.file_directories[fdir]->file_sub_count;area++) {
        free(conf.file_directories[fdir]->file_subs[area]->name);
        free(conf.file_directories[fdir]->file_subs[area]->database);
        free(conf.file_directories[fdir]->file_subs[area]->upload_path);
        free(conf.file_directories[fdir]->file_subs[area]);
 
    }

    free(conf.file_directories[fdir]->file_subs);
    free(conf.file_directories[fdir]->name);
    free(conf.file_directories[fdir]->path);

    for (i=fdir;i<conf.file_directory_count - 1;i++) {
        conf.file_directories[i]= conf.file_directories[i+1];
    }

    conf.file_directory_count--;
    conf.file_directories = (struct file_directory **)realloc(conf.file_directories, sizeof(struct file_directory *) * conf.file_directory_count);
}

void edit_file_directory(int fdir) {
    char *itemList[] = {"Name",
                        "Path & Filename",
                        "Visible Sec. Level",
                        "Edit Sub Directories",
                        "Delete Directory"};
    
    char buffer[1024];
    int selection;

    snprintf(buffer, 1024, "</B/32>%s<!32>", conf.file_directories[fdir]->name);

    CDKSCROLL *editDirList = newCDKScroll(cdkscreen, 5, 5, RIGHT, 8, 30, buffer, itemList, 5, FALSE, A_STANDOUT, TRUE, FALSE);
    
    while (1) {
        selection = activateCDKScroll(editDirList, 0);
        if (editDirList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_file_directory_name(fdir);
                break;
            case 1:
                edit_file_directory_file(fdir);
                break;
            case 2:
                choose_sec_level(&conf.file_directories[fdir]->sec_level, 7, 7, conf.file_directories[fdir]->sec_level);
                break;
            case 3:
                edit_file_subdirs(fdir);
                break;
            case 4:
                delete_file_directory(fdir);
                destroyCDKScroll(editDirList);
                return;
            default:
                break;
        }
    }

    destroyCDKScroll(editDirList);
}

void add_new_file_directory() {
    char areapath[PATH_MAX];
    conf.file_directories = (struct file_directory **)realloc(conf.file_directories, sizeof(struct file_directory *) * (conf.file_directory_count + 1));
    conf.file_directories[conf.file_directory_count] = (struct file_directory *)malloc(sizeof(struct file_directory));    
    conf.file_directories[conf.file_directory_count]->file_subs = (struct file_sub **)malloc(sizeof(struct file_sub *));
    conf.file_directories[conf.file_directory_count]->file_subs[0] = (struct file_sub *)malloc(sizeof(struct file_sub));
    conf.file_directories[conf.file_directory_count]->file_subs[0]->name = strdup("New Sub Directory");
    snprintf(areapath, PATH_MAX, "%s/new_area", conf.bbs_path);
    conf.file_directories[conf.file_directory_count]->file_subs[0]->database = strdup(areapath);
    conf.file_directories[conf.file_directory_count]->file_subs[0]->upload_path = strdup(conf.bbs_path);
    conf.file_directories[conf.file_directory_count]->file_subs[0]->upload_sec_level = conf.newuserlvl;
    conf.file_directories[conf.file_directory_count]->file_subs[0]->download_sec_level = conf.newuserlvl;
    conf.file_directories[conf.file_directory_count]->file_sub_count = 1;
    
    conf.file_directories[conf.file_directory_count]->name = strdup("New Directory");
    snprintf(areapath, PATH_MAX, "%s/new_dir.ini", conf.config_path);
    conf.file_directories[conf.file_directory_count]->path = strdup(areapath);
    conf.file_directories[conf.file_directory_count]->sec_level = conf.newuserlvl;

    conf.file_directory_count ++;

    edit_file_directory(conf.file_directory_count-1);
}


void file_directories() {
    char **itemlist;
    int selection;
    int i;
    int dircount;

    while (1) {
        itemlist = (char **)malloc(sizeof(char *) * (conf.file_directory_count + 1));
        dircount = conf.file_directory_count;
        itemlist[0] = strdup("Add File Directory");

        for (i=0;i<dircount;i++) {
            itemlist[i+1] = strdup(conf.file_directories[i]->name);
        }

        CDKSCROLL *fileDirList = newCDKScroll(cdkscreen, 3, 3, RIGHT, 12, 30, "</B/32>File Directories<!32>", itemlist, dircount + 1, FALSE, A_STANDOUT, TRUE, FALSE);


        selection = activateCDKScroll(fileDirList, 0);
        if (fileDirList->exitType == vESCAPE_HIT) {
            destroyCDKScroll(fileDirList);
            for (i=0;i<dircount+1;i++) {
                free(itemlist[i]);
            }
            free(itemlist);
            break;
        }
        if (selection == 0) {
            // add new
            add_new_file_directory();
        } else {
            // edit existing
            edit_file_directory(selection - 1);
        }
        destroyCDKScroll(fileDirList);
        for (i=0;i<dircount+1;i++) {
            free(itemlist[i]);
        }
        free(itemlist);
    }
}