#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void edit_txtfile_name(int txtfile) {
    char *entrytext;
    CDKENTRY *txtFileName = newCDKEntry(cdkscreen, 7, 7, "</B/32>Text File Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 64, TRUE, FALSE);
    
    setCDKEntry(txtFileName, conf.text_files[txtfile]->name, 1, 64, TRUE);

    entrytext = activateCDKEntry(txtFileName, 0);

    if (txtFileName->exitType == vNORMAL) {
        if (conf.text_files[txtfile]->name != NULL) {
            free(conf.text_files[txtfile]->name);
        }
        conf.text_files[txtfile]->name = strdup(entrytext);
    }
    destroyCDKEntry(txtFileName);
}

void edit_txtfile_file(int txtfile) {
    char *entrytext;
    CDKENTRY *txtFileFile = newCDKEntry(cdkscreen, 7, 7, "</B/32>Text File Filename<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(txtFileFile, conf.text_files[txtfile]->path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(txtFileFile, 0);

    if (txtFileFile->exitType == vNORMAL) {
        if (conf.text_files[txtfile]->path != NULL) {
            free(conf.text_files[txtfile]->path);
        }
        conf.text_files[txtfile]->path = strdup(entrytext);
    }
    destroyCDKEntry(txtFileFile);
}

void delete_txtfile(int txtfile) {
    int i;
    free(conf.text_files[txtfile]->name);
    free(conf.text_files[txtfile]->path);
    free(conf.text_files[txtfile]);

    for (i=txtfile;i<conf.text_file_count-1;i++) {
        conf.text_files[txtfile] = conf.text_files[txtfile + 1];
    }

    conf.text_file_count--;

    conf.text_files = (struct text_file **)realloc(conf.text_files, sizeof(struct text_file *) * conf.text_file_count);
}

void edit_text_file(int txtfile) {
    char *itemList[] = {"Name",
                        "Path and Filename",
                        "Delete Text File"};
    
    char buffer[1024];
    int selection;

    snprintf(buffer, 1024, "</B/32>%s<!32>", conf.text_files[txtfile]->name);
    CDKSCROLL *editTxtFiles = newCDKScroll(cdkscreen, 5, 5, RIGHT, 6, 30, buffer, itemList, 3, FALSE, A_STANDOUT, TRUE, FALSE);
    
    while (1) {
        selection = activateCDKScroll(editTxtFiles, 0);
        if (editTxtFiles->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_txtfile_name(txtfile);
                break;
            case 1:
                edit_txtfile_file(txtfile);
                break;
            case 2:
                delete_txtfile(txtfile);
                destroyCDKScroll(editTxtFiles);
                return;
            default:
                break;
        }
    }

    destroyCDKScroll(editTxtFiles);
}

void add_new_text_file() {
    char filepath[PATH_MAX];
    conf.text_files = (struct text_file **)realloc(conf.text_files, sizeof(struct text_file *) * (conf.text_file_count + 1));
    conf.text_files[conf.text_file_count] = (struct text_file *)malloc(sizeof(struct text_file));
    conf.text_files[conf.text_file_count]->name = strdup("New Text File");
    snprintf(filepath, PATH_MAX, "%s/newfile.ans", conf.ansi_path);
    conf.text_files[conf.text_file_count]->path = strdup(filepath);
    conf.text_file_count++;

    edit_text_file(conf.text_file_count - 1);
}

void textfiles() {
    char **itemlist;
    int selection;
    int i;
    int txtcount;

    while (1) {
        itemlist = (char **)malloc(sizeof(char *) * (conf.text_file_count + 1));
        txtcount = conf.text_file_count;
        itemlist[0] = strdup("Add Text File");

        for (i=0;i<txtcount;i++) {
            itemlist[i+1] = strdup(conf.text_files[i]->name);
        }

        CDKSCROLL *txtFileList = newCDKScroll(cdkscreen, 3, 3, RIGHT, 12, 30, "</B/32>Text Files<!32>", itemlist, txtcount + 1, FALSE, A_STANDOUT, TRUE, FALSE);

        selection = activateCDKScroll(txtFileList, 0);
        if (txtFileList->exitType == vESCAPE_HIT) {
            destroyCDKScroll(txtFileList);
            for (i=0;i<txtcount+1;i++) {
                free(itemlist[i]);
            }
            free(itemlist);
            break;
        }
        if (selection == 0) {
            // add new
            add_new_text_file();
        } else {
            // edit existing
            edit_text_file(selection - 1);
        }
        destroyCDKScroll(txtFileList);
        for (i=0;i<txtcount+1;i++) {
            free(itemlist[i]);
        }
        free(itemlist);
    }    
}