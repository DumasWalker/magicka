#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void edit_archiver_name(int selected) {
    char *entrytext;
    CDKENTRY *arcName = newCDKEntry(cdkscreen, 7, 7, "</B/32>Archiver Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 64, TRUE, FALSE);
    
    setCDKEntry(arcName, conf.archivers[selected]->name, 1, 64, TRUE);

    entrytext = activateCDKEntry(arcName, 0);

    if (arcName->exitType == vNORMAL) {
        if (conf.archivers[selected]->name != NULL) {
            free(conf.archivers[selected]->name);
        }
        conf.archivers[selected]->name = strdup(entrytext);
    }
    destroyCDKEntry(arcName);
}

void edit_archiver_extension(int selected) {
    char *entrytext;
    CDKENTRY *arcExt = newCDKEntry(cdkscreen, 7, 7, "</B/32>Archiver Extension<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 12, TRUE, FALSE);
    
    setCDKEntry(arcExt, conf.archivers[selected]->extension, 1, 12, TRUE);

    entrytext = activateCDKEntry(arcExt, 0);

    if (arcExt->exitType == vNORMAL) {
        if (conf.archivers[selected]->extension != NULL) {
            free(conf.archivers[selected]->extension);
        }
        conf.archivers[selected]->extension = strdup(entrytext);
    }
    destroyCDKEntry(arcExt);
}

void edit_archiver_unpack(int selected) {
    char *entrytext;
    CDKENTRY *arcUnpack = newCDKEntry(cdkscreen, 7, 7, "</B/32>Archiver Unpack Command<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, PATH_MAX, TRUE, FALSE);
    
    setCDKEntry(arcUnpack, conf.archivers[selected]->unpack, 1, PATH_MAX, TRUE);

    entrytext = activateCDKEntry(arcUnpack, 0);

    if (arcUnpack->exitType == vNORMAL) {
        if (conf.archivers[selected]->unpack != NULL) {
            free(conf.archivers[selected]->unpack);
        }
        conf.archivers[selected]->unpack = strdup(entrytext);
    }
    destroyCDKEntry(arcUnpack);
}

void edit_archiver_pack(int selected) {
    char *entrytext;
    CDKENTRY *arcPack = newCDKEntry(cdkscreen, 7, 7, "</B/32>Archiver Pack Command<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, PATH_MAX, TRUE, FALSE);
    
    setCDKEntry(arcPack, conf.archivers[selected]->pack, 1, PATH_MAX, TRUE);

    entrytext = activateCDKEntry(arcPack, 0);

    if (arcPack->exitType == vNORMAL) {
        if (conf.archivers[selected]->pack != NULL) {
            free(conf.archivers[selected]->pack);
        }
        conf.archivers[selected]->pack = strdup(entrytext);
    }
    destroyCDKEntry(arcPack);
}

void display_archiver_error() {
    char *message[] = {"Must have at least one Archiver!"};
    char *buttons[] = {" OK "}; 
    CDKDIALOG *dialog = newCDKDialog(cdkscreen, 7, 7, message, 1, buttons, 1, A_STANDOUT, FALSE, TRUE, FALSE);
    activateCDKDialog(dialog, 0);
    destroyCDKDialog(dialog);
}

void delete_archiver(int selected) {
    int i;

    if (conf.archiver_count == 1) {
        display_archiver_error();
        return;
    }

    free(conf.archivers[selected]->name);
    free(conf.archivers[selected]->extension);
    free(conf.archivers[selected]->unpack);
    free(conf.archivers[selected]->pack);
    free(conf.archivers[selected]);

    for (i=selected; i< conf.archiver_count-1;i++) {
        conf.archivers[i] = conf.archivers[i+1];
    }

    conf.archiver_count--;
    conf.archivers = (struct archiver **)realloc(conf.archivers, sizeof(struct archiver *) * (conf.archiver_count));
}

void edit_archiver(int selected) {
    char *itemList[] = {"Name",
                        "Extension",
                        "Unpack Command",
                        "Pack Command",
                        "Delete Archiver"};
    char buffer[1024];
    int selection;

    snprintf(buffer, 1024, "</B/32>%s<!32>", conf.archivers[selected]->name);

    CDKSCROLL *arcEditList = newCDKScroll(cdkscreen, 5, 5, RIGHT, 8, 30, buffer, itemList, 5, FALSE, A_STANDOUT, TRUE, FALSE);
    
    while (1) {
        selection = activateCDKScroll(arcEditList, 0);
        if (arcEditList->exitType == vESCAPE_HIT) {
            break;
        }
        switch(selection) {
            case 0:
                edit_archiver_name(selected);
                break;
            case 1:
                edit_archiver_extension(selected);
                break;
            case 2:
                edit_archiver_unpack(selected);
                break;
            case 3:
                edit_archiver_pack(selected);
                break;
            case 4:
                delete_archiver(selected);
                destroyCDKScroll(arcEditList); 
                return;
            default:
                break;
        }
    }

    destroyCDKScroll(arcEditList);                        
}

void add_archiver() {
    conf.archivers = (struct archiver **)realloc(conf.archivers, sizeof(struct archiver *) * (conf.archiver_count + 1));

    conf.archivers[conf.archiver_count] = (struct archiver *)malloc(sizeof(struct archiver));
    conf.archivers[conf.archiver_count]->name = strdup("New Archiver");
    conf.archivers[conf.archiver_count]->extension = strdup("new");
    conf.archivers[conf.archiver_count]->unpack = strdup("newarc -u *a -d *d");
    conf.archivers[conf.archiver_count]->pack = strdup("newarc -p *a -f *f");
    conf.archiver_count++;

    edit_archiver(conf.archiver_count - 1);
}

void archivers(void) {
    char **itemlist;
    int selection;
    int i;
    int arccount;

    while (1) {
        itemlist = (char **)malloc(sizeof(char *) * (conf.archiver_count + 1));
        arccount = conf.archiver_count;
        itemlist[0] = strdup("Add Archiver");

        for (i=0;i<arccount;i++) {
            itemlist[i+1] = strdup(conf.archivers[i]->name);
        }

        CDKSCROLL *arcList = newCDKScroll(cdkscreen, 3, 3, RIGHT, 12, 30, "</B/32>Archivers<!32>", itemlist, arccount + 1, FALSE, A_STANDOUT, TRUE, FALSE);

        selection = activateCDKScroll(arcList, 0);
        if (arcList->exitType == vESCAPE_HIT) {
            destroyCDKScroll(arcList);
            for (i=0;i<arccount+1;i++) {
                free(itemlist[i]);
            }
            free(itemlist);
            break;
        }
        if (selection == 0) {
            // add new
            add_archiver();
        } else {
            // edit existing
            edit_archiver(selection - 1);
        }
        destroyCDKScroll(arcList);
        for (i=0;i<arccount+1;i++) {
            free(itemlist[i]);
        }
        free(itemlist);
    }
}