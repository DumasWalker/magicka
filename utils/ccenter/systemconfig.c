#include <curses.h>
#include <cdk.h>
#include "ccenter.h"

extern struct bbs_config conf;
extern CDKSCREEN *cdkscreen;

void bbs_name(void) {
    char *entrytext;
    CDKENTRY *bbsNameEntry = newCDKEntry(cdkscreen, 5, 5, "</B/32>BBS Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 32, 1, 32, TRUE, FALSE);
    
    setCDKEntry(bbsNameEntry, conf.bbs_name, 1, 32, TRUE);

    entrytext = activateCDKEntry(bbsNameEntry, 0);

    if (bbsNameEntry->exitType == vNORMAL) {
        if (conf.bbs_name != NULL) {
            free(conf.bbs_name);
        }
        conf.bbs_name = strdup(entrytext);
    }
    destroyCDKEntry(bbsNameEntry);
}

void sysop_name(void) {
    char *entrytext;
    CDKENTRY *sysopNameEntry = newCDKEntry(cdkscreen, 5, 5, "</B/32>Sysop Name<!32>", NULL, A_NORMAL, ' ', vMIXED, 32, 1, 32, TRUE, FALSE);
    
    setCDKEntry(sysopNameEntry, conf.sysop_name, 1, 32, TRUE);

    entrytext = activateCDKEntry(sysopNameEntry, 0);

    if (sysopNameEntry->exitType == vNORMAL) {
        if (conf.sysop_name != NULL) {
            free(conf.sysop_name);
        }
        conf.sysop_name = strdup(entrytext);
    }
    destroyCDKEntry(sysopNameEntry);
}

void number_of_nodes(void) {
    char *entrytext;
    char buffer[4];
    int newnum;
    CDKENTRY *nodeNumEntry = newCDKEntry(cdkscreen, 5, 5, "</B/32>Number of Nodes (1-255)<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 3, TRUE, FALSE);
    
    snprintf(buffer, 4, "%d", conf.nodes);

    setCDKEntry(nodeNumEntry, buffer, 1, 3, TRUE);

    entrytext = activateCDKEntry(nodeNumEntry, 0);

    if (nodeNumEntry->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 0 && newnum < 256) {
            conf.nodes = newnum;
        }
    }
    destroyCDKEntry(nodeNumEntry); 
}

void main_aka() {
    char *entrytext;
    char buffer[128];
    struct fido_addr *new_addr;
    CDKENTRY *mainAKAEntry = newCDKEntry(cdkscreen, 7, 7, "</B/32>Main AKA<!32>", NULL, A_NORMAL, ' ', vMIXED, 32, 1, 32, TRUE, FALSE);
    
    snprintf(buffer, 128, "%d:%d/%d.%d", conf.main_aka->zone, conf.main_aka->net, conf.main_aka->node, conf.main_aka->point);

    setCDKEntry(mainAKAEntry, buffer, 1, 32, TRUE);

    entrytext = activateCDKEntry(mainAKAEntry, 0);

    if (mainAKAEntry->exitType == vNORMAL) {
        new_addr = parse_fido_addr(entrytext);
        if (new_addr != NULL) {
            if (conf.main_aka != NULL) {
                free(conf.main_aka);
            }
            conf.main_aka = new_addr;
        }
    }
    destroyCDKEntry(mainAKAEntry);
}

void default_tagline(void) {
    char *entrytext;
    CDKENTRY *defaultTagline = newCDKEntry(cdkscreen, 7, 7, "</B/32>Default Tagline<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 80, TRUE, FALSE);
    
    setCDKEntry(defaultTagline, conf.default_tagline, 1, 80, TRUE);

    entrytext = activateCDKEntry(defaultTagline, 0);

    if (defaultTagline->exitType == vNORMAL) {
        if (conf.default_tagline != NULL) {
            free(conf.default_tagline);
        }
        conf.default_tagline = strdup(entrytext);
    }
    destroyCDKEntry(defaultTagline);
}

void external_editor_cmd(void) {
    char *entrytext;
    CDKENTRY *extEditCmd = newCDKEntry(cdkscreen, 9, 9, "</B/32>External Editor Command<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(extEditCmd, conf.external_editor_cmd, 1, 1024, TRUE);

    entrytext = activateCDKEntry(extEditCmd, 0);

    if (extEditCmd->exitType == vNORMAL) {
        if (conf.external_editor_cmd != NULL) {
            free(conf.external_editor_cmd);
        }
        conf.external_editor_cmd = strdup(entrytext);
    }
    destroyCDKEntry(extEditCmd);
}

void external_editor_stdio() {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *extEditStdio = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>External Editor STDIO<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.external_editor_stdio == 1) {
        setCDKScrollCurrent(extEditStdio, 0);
    } else {
        setCDKScrollCurrent(extEditStdio, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(extEditStdio, 0);
        if (extEditStdio->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.external_editor_stdio = 1;
                doexit = 1;
                break;
            case 1:
                conf.external_editor_stdio = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(extEditStdio);
}

void external_editor() {
    char *itemList[] = {"Command",
                        "STDIO Redirection"};
    int selection;
    CDKSCROLL *extEditOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 5, 30, "</B/32>External Editor Config<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(extEditOpts, 0);
        if (extEditOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                external_editor_cmd();
                break;
            case 1:
                external_editor_stdio();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(extEditOpts);
}

void qwk_opts_name(void) {
    char *entrytext;
    CDKENTRY *qwkOpsName = newCDKEntry(cdkscreen, 9, 9, "</B/32>QWK/Bluewave Name (8 Chars Max)<!32>", NULL, A_NORMAL, ' ', vUMIXED, 16, 1, 8, TRUE, FALSE);
    
    setCDKEntry(qwkOpsName, conf.bwave_name, 1, 8, TRUE);

    entrytext = activateCDKEntry(qwkOpsName, 0);

    if (qwkOpsName->exitType == vNORMAL) {
        if (conf.bwave_name != NULL) {
            free(conf.bwave_name);
        }
        conf.bwave_name = strdup(entrytext);
    }
    destroyCDKEntry(qwkOpsName);
}

void qwk_opts_max(void) {
    char *entrytext;
    char buffer[7];
    int newnum;
    CDKENTRY *qwkOptsMax = newCDKEntry(cdkscreen, 9, 9, "</B/32>Max Messages Per Packet<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 6, TRUE, FALSE);
    
    snprintf(buffer, 7, "%d", conf.bwave_max_msgs);

    setCDKEntry(qwkOptsMax, buffer, 1, 3, TRUE);

    entrytext = activateCDKEntry(qwkOptsMax, 0);

    if (qwkOptsMax->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 0) {
            conf.bwave_max_msgs = newnum;
        }
    }
    destroyCDKEntry(qwkOptsMax); 
}

void qwk_opts() {
    char *itemList[] = {"QWK Name",
                        "QWK Max Messages"};
    int selection;
    CDKSCROLL *qwkOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 5, 30, "</B/32>QWK/Bluewave Options<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(qwkOpts, 0);
        if (qwkOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                qwk_opts_name();
                break;
            case 1:
                qwk_opts_max();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(qwkOpts);
}

void message_area_opts() {
    char *itemList[] = {"Main AKA",
                        "Default Tagline",
                        "External Editor",
                        "QWK/Bluewave Options"};
    int selection;
    CDKSCROLL *msgAreaOpts = newCDKScroll(cdkscreen, 5, 5, RIGHT, 7, 30, "</B/32>Message Area Options<!32>", itemList, 4,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(msgAreaOpts, 0);
        if (msgAreaOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                main_aka();
                break;
            case 1:
                default_tagline();
                break;
            case 2:
                external_editor();
                break;
            case 3:
                qwk_opts();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(msgAreaOpts);
}

void choose_sec_level(int *result, int x, int y, int selected) {

    int *lvls;
    int count;
    int res;
    int i;
    int s = -1;

    if (!get_valid_seclevels(&lvls, &count)) {
        return;
    }

    char **itemlist;

    itemlist = (char **)malloc(sizeof(char *) * count);

    for (i=0;i<count;i++) {
        itemlist[i] = (char *)malloc(sizeof(char) * 4);

        snprintf(itemlist[i], 4, "%d", lvls[i]);
        if (lvls[i] == selected) {
            s = i;
        }
    }

    int selection;
    CDKSCROLL *secLevelOpts = newCDKScroll(cdkscreen, x, y, RIGHT, 10, 30, "</B/32>Choose Sec Level<!32>", itemlist, count,FALSE, A_STANDOUT, TRUE, FALSE);

    if (s != -1) {
        setCDKScrollCurrent(secLevelOpts, s);
    }

    while(1) {
        selection = activateCDKScroll(secLevelOpts, 0);
        if (secLevelOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        res = (lvls[selection]);

        *result = res;
        break;
    }
    destroyCDKScroll(secLevelOpts);

    for (i=0;i<count;i++) {
        free(itemlist[i]);
    }

    free(itemlist);
    free(lvls);    
}

void sec_level_opts() {
    char *itemList[] = {"New User Security Level",
                        "AutoMessage Write Sec. Level"};
    int selection;
    int ret;
    CDKSCROLL *secLevelOpts = newCDKScroll(cdkscreen, 5, 5, RIGHT, 5, 30, "</B/32>Default Security Levels<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(secLevelOpts, 0);
        if (secLevelOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                choose_sec_level(&ret, 7, 7, conf.newuserlvl);
                conf.newuserlvl = ret;
                break;
            case 1:
                choose_sec_level(&ret, 7, 7, conf.automsgwritelvl);
                conf.automsgwritelvl = ret;
                break;                                
            default:
                break;
        }
    }
    destroyCDKScroll(secLevelOpts);
}

void telnet_port(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *telnetPort = newCDKEntry(cdkscreen, 7, 7, "</B/32>Telnet Port 1025-65535<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.telnet_port);

    setCDKEntry(telnetPort, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(telnetPort, 0);

    if (telnetPort->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.telnet_port = newnum;
        }
    }
    destroyCDKEntry(telnetPort); 
}

void ssh_enabled() {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *sshEnabled = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Enable SSH<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.ssh_server == 1) {
        setCDKScrollCurrent(sshEnabled, 0);
    } else {
        setCDKScrollCurrent(sshEnabled, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(sshEnabled, 0);
        if (sshEnabled->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.ssh_server = 1;
                doexit = 1;
                break;
            case 1:
                conf.ssh_server = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(sshEnabled);
}

void ssh_port(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *sshPort = newCDKEntry(cdkscreen, 9, 9, "</B/32>SSH Port 1025-65535<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.ssh_port);

    setCDKEntry(sshPort, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(sshPort, 0);

    if (sshPort->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.ssh_port = newnum;
        }
    }
    destroyCDKEntry(sshPort); 
}

void ssh_dsa_key(void) {
    char *entrytext;
    CDKENTRY *sshDSAKey = newCDKEntry(cdkscreen, 9, 9, "</B/32>SSH DSA Key<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(sshDSAKey, conf.ssh_dsa_key, 1, 1024, TRUE);

    entrytext = activateCDKEntry(sshDSAKey, 0);

    if (sshDSAKey->exitType == vNORMAL) {
        if (conf.ssh_dsa_key != NULL) {
            free(conf.ssh_dsa_key);
        }
        conf.ssh_dsa_key = strdup(entrytext);
    }
    destroyCDKEntry(sshDSAKey);
}

void ssh_rsa_key(void) {
    char *entrytext;
    CDKENTRY *sshRSAKey = newCDKEntry(cdkscreen, 9, 9, "</B/32>SSH RSA Key<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(sshRSAKey, conf.ssh_rsa_key, 1, 1024, TRUE);

    entrytext = activateCDKEntry(sshRSAKey, 0);

    if (sshRSAKey->exitType == vNORMAL) {
        if (conf.ssh_rsa_key != NULL) {
            free(conf.ssh_rsa_key);
        }
        conf.ssh_rsa_key = strdup(entrytext);
    }
    destroyCDKEntry(sshRSAKey);
}

void ssh_opts() {
    char *itemList[] = {"SSH Enabled",
                        "SSH Port",
                        "SSH DSA Key",
                        "SSH RSA Key"};
    int selection;
    CDKSCROLL *sshOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 7, 30, "</B/32>SSH Options<!32>", itemList, 4,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(sshOpts, 0);
        if (sshOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                ssh_enabled();
                break;
            case 1:
                ssh_port();
                break;
            case 2:
                ssh_dsa_key();
                break;
            case 3:
                ssh_rsa_key();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(sshOpts);
}

void www_enabled() {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *wwwEnabled = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Enable HTTP<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.www_server == 1) {
        setCDKScrollCurrent(wwwEnabled, 0);
    } else {
        setCDKScrollCurrent(wwwEnabled, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(wwwEnabled, 0);
        if (wwwEnabled->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.www_server = 1;
                doexit = 1;
                break;
            case 1:
                conf.www_server = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(wwwEnabled);
}

void www_port(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *wwwPort = newCDKEntry(cdkscreen, 9, 9, "</B/32>HTTP Port 1025-65535<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.www_port);

    setCDKEntry(wwwPort, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(wwwPort, 0);

    if (wwwPort->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.www_port = newnum;
        }
    }
    destroyCDKEntry(wwwPort); 
}

void www_path(void) {
    char *entrytext;
    CDKENTRY *wwwPath = newCDKEntry(cdkscreen, 9, 9, "</B/32>HTTP Root Path<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(wwwPath, conf.www_path, 1, 1024, TRUE);

    entrytext = activateCDKEntry(wwwPath, 0);

    if (wwwPath->exitType == vNORMAL) {
        if (conf.www_path != NULL) {
            free(conf.www_path);
        }
        conf.www_path = strdup(entrytext);
    }
    destroyCDKEntry(wwwPath);
}

void www_opts() {
    char *itemList[] = {"HTTP Enabled",
                        "HTTP Port",
                        "HTTP Root Path"};
    int selection;
    CDKSCROLL *wwwOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 6, 30, "</B/32>HTTP Options<!32>", itemList, 3,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(wwwOpts, 0);
        if (wwwOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                www_enabled();
                break;
            case 1:
                www_port();
                break;
            case 2:
                www_path();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(wwwOpts);
}

void chat_server(void) {
    char *entrytext;
    CDKENTRY *chatServer = newCDKEntry(cdkscreen, 9, 9, "</B/32>MagiChat Server<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 0, 1024, TRUE, FALSE);
    
    if (conf.mgchat_server != NULL) {
        setCDKEntry(chatServer, conf.mgchat_server, 1, 1024, TRUE);
    }

    entrytext = activateCDKEntry(chatServer, 0);

    if (chatServer->exitType == vNORMAL) {
        if (conf.mgchat_server != NULL) {
            free(conf.mgchat_server);
        }
        if (strlen(entrytext) > 0) {
            conf.mgchat_server = strdup(entrytext);
        } else {
            conf.mgchat_server = NULL;
        }
    }
    destroyCDKEntry(chatServer);
}

void chat_port(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *chatPort = newCDKEntry(cdkscreen, 9, 9, "</B/32>MagiChat Port 1025-65535<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.mgchat_port);

    setCDKEntry(chatPort, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(chatPort, 0);

    if (chatPort->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.mgchat_port = newnum;
        }
    }
    destroyCDKEntry(chatPort); 
}

void chat_bbstag(void) {
    char *entrytext;
    CDKENTRY *chatTag = newCDKEntry(cdkscreen, 9, 9, "</B/32>MagiChat BBS Tag<!32>", NULL, A_NORMAL, ' ', vMIXED, 32, 1, 16, TRUE, FALSE);
    
    setCDKEntry(chatTag, conf.mgchat_bbstag, 1, 16, TRUE);

    entrytext = activateCDKEntry(chatTag, 0);

    if (chatTag->exitType == vNORMAL) {
        if (conf.mgchat_bbstag != NULL) {
            free(conf.mgchat_bbstag);
        }
        conf.mgchat_bbstag = strdup(entrytext);
    }
    destroyCDKEntry(chatTag);
}

void chat_opts() {
    char *itemList[] = {"MagiChat Server",
                        "MagiChat Port",
                        "MagiChat BBS Tag"};
    int selection;
    CDKSCROLL *chatOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 6, 30, "</B/32>MagiChat Options<!32>", itemList, 3,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(chatOpts, 0);
        if (chatOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                chat_server();
                break;
            case 1:
                chat_port();
                break;
            case 2:
                chat_bbstag();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(chatOpts);
}

void broadcast_enable() {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *broadcastEnabled = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Enable Broadcast<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.broadcast_enable == 1) {
        setCDKScrollCurrent(broadcastEnabled, 0);
    } else {
        setCDKScrollCurrent(broadcastEnabled, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(broadcastEnabled, 0);
        if (broadcastEnabled->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.broadcast_enable = 1;
                doexit = 1;
                break;
            case 1:
                conf.broadcast_enable = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(broadcastEnabled);
}

void broadcast_port(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *broadcastPort = newCDKEntry(cdkscreen, 9, 9, "</B/32>Broadcast Port 1025-65535<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.broadcast_port);

    setCDKEntry(broadcastPort, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(broadcastPort, 0);

    if (broadcastPort->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.broadcast_port = newnum;
        }
    }
    destroyCDKEntry(broadcastPort); 
}

void broadcast_address(void) {
    char *entrytext;
    CDKENTRY *broadcastAddr = newCDKEntry(cdkscreen, 9, 9, "</B/32>Broadcast Address<!32>", NULL, A_NORMAL, ' ', vMIXED, 48, 1, 1024, TRUE, FALSE);
    
    setCDKEntry(broadcastAddr, conf.broadcast_address, 1, 1024, TRUE);

    entrytext = activateCDKEntry(broadcastAddr, 0);

    if (broadcastAddr->exitType == vNORMAL) {
        if (conf.broadcast_address != NULL) {
            free(conf.broadcast_address);
        }
        conf.broadcast_address = strdup(entrytext);
    }
    destroyCDKEntry(broadcastAddr);
}

void broadcast_opts() {
    char *itemList[] = {"Broadcast Enable",
                        "Broadcast Port",
                        "Broadcast Address"};
    int selection;
    CDKSCROLL *broadcastOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 6, 30, "</B/32>Broadcast Options<!32>", itemList, 3,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(broadcastOpts, 0);
        if (broadcastOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                broadcast_enable();
                break;
            case 1:
                broadcast_port();
                break;
            case 2:
                broadcast_address();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(broadcastOpts);
}

void ipguard_enable() {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *ipguardEnabled = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Enable IPGuard<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.ipguard_enable == 1) {
        setCDKScrollCurrent(ipguardEnabled, 0);
    } else {
        setCDKScrollCurrent(ipguardEnabled, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(ipguardEnabled, 0);
        if (ipguardEnabled->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.ipguard_enable = 1;
                doexit = 1;
                break;
            case 1:
                conf.ipguard_enable = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(ipguardEnabled);
}

void ipguard_timeout(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *ipguardTimeout = newCDKEntry(cdkscreen, 9, 9, "</B/32>IP Guard Timeout<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.ipguard_timeout);

    setCDKEntry(ipguardTimeout, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(ipguardTimeout, 0);

    if (ipguardTimeout->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.ipguard_timeout = newnum;
        }
    }
    destroyCDKEntry(ipguardTimeout); 
}

void ipguard_tries(void) {
    char *entrytext;
    char buffer[6];
    int newnum;
    CDKENTRY *ipguardTries = newCDKEntry(cdkscreen, 9, 9, "</B/32>IP Guard Tries<!32>", NULL, A_NORMAL, ' ', vINT, 32, 1, 5, TRUE, FALSE);
    
    snprintf(buffer, 6, "%d", conf.ipguard_tries);

    setCDKEntry(ipguardTries, buffer, 1, 5, TRUE);

    entrytext = activateCDKEntry(ipguardTries, 0);

    if (ipguardTries->exitType == vNORMAL) {
        newnum = atoi(entrytext);
        if (newnum > 1024 && newnum < 65536) {
            conf.ipguard_tries = newnum;
        }
    }
    destroyCDKEntry(ipguardTries); 
}

void ipguard_opts() {
    char *itemList[] = {"IPGuard Enable",
                        "IPGuard Timeout",
                        "IPGuard Tries"};
    int selection;
    CDKSCROLL *ipGuardOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 6, 30, "</B/32>IPGuard Options<!32>", itemList, 3,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(ipGuardOpts, 0);
        if (ipGuardOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                ipguard_enable();
                break;
            case 1:
                ipguard_timeout();
                break;
            case 2:
                ipguard_tries();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(ipGuardOpts);
}

void fork_enable() {
    char *itemList[] = {"True",
                        "False"};
    int selection;
    int doexit = 0;
    CDKSCROLL *forkEnabled = newCDKScroll(cdkscreen, 9, 9, RIGHT, 5, 30, "</B/32>Fork to Background<!32>", itemList, 2,FALSE, A_STANDOUT, TRUE, FALSE);

    if (conf.fork == 1) {
        setCDKScrollCurrent(forkEnabled, 0);
    } else {
        setCDKScrollCurrent(forkEnabled, 1);
    }

    while(!doexit) {
        selection = activateCDKScroll(forkEnabled, 0);
        if (forkEnabled->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                conf.fork = 1;
                doexit = 1;
                break;
            case 1:
                conf.fork = 0;
                doexit = 1;
                break;            
            default:
                break;
        }
    }
    destroyCDKScroll(forkEnabled);
}

void misc_opts() {
    char *itemList[] = {"Fork"};
    int selection;
    CDKSCROLL *miscOpts = newCDKScroll(cdkscreen, 7, 7, RIGHT, 4, 30, "</B/32>Misc Options<!32>", itemList, 1,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(miscOpts, 0);
        if (miscOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                fork_enable();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(miscOpts);
}

void server_opts() {
    char *itemList[] = {"Telnet Port",
                        "SSH Options",
                        "HTTP Options",
                        "MagiChat Options",
                        "Broadcast Options",
                        "IP Guard Options",
                        "Misc Options"};
    int selection;
    CDKSCROLL *svrOpts = newCDKScroll(cdkscreen, 5, 5, RIGHT, 10, 30, "</B/32>Server/Port Options<!32>", itemList, 7,FALSE, A_STANDOUT, TRUE, FALSE);

    while(1) {
        selection = activateCDKScroll(svrOpts, 0);
        if (svrOpts->exitType == vESCAPE_HIT) {
            break;
        } 
        switch(selection) {
            case 0:
                telnet_port();
                break;
            case 1:
                ssh_opts();
                break;
            case 2:
                www_opts();
                break;
            case 3:
                chat_opts();
                break;
            case 4:
                broadcast_opts();
                break;
            case 5:
                ipguard_opts();
                break;
            case 6:
                misc_opts();
                break;
            default:
                break;
        }
    }
    destroyCDKScroll(svrOpts);
}

void system_config(void) {

    char *itemList[] = {"BBS Name", 
                        "Sysop Name", 
                        "Number of Nodes", 
                        "Message Area Options",
                        "Default Security Levels",
                        "Servers and Ports"
                        };
    int selection;
    CDKSCROLL *sysConfigItemList = newCDKScroll(cdkscreen, 3, 3, RIGHT, 9, 30, "</B/32>System Config<!32>", itemList, 6,FALSE, A_STANDOUT, TRUE, FALSE);

    while (1) {
        selection = activateCDKScroll(sysConfigItemList, 0);
        if (sysConfigItemList->exitType == vESCAPE_HIT) {
            break;
        }
        switch (selection) {
            case 0:
                bbs_name();
                break;
            case 1:
                sysop_name();
                break;
            case 2:
                number_of_nodes();
                break;
            case 3:
                message_area_opts();
                break;
            case 4:
                sec_level_opts();
                break;
            case 5:
                server_opts();
                break;
            default:
                break;
        }
    }

    destroyCDKScroll(sysConfigItemList);
}