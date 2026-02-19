/*
 The contents of this file are subject to the Mozilla Public License
 Version 1.1 (the "License"); you may not use this file except in
 compliance with the License. You may obtain a copy of the License at
 http://www.mozilla.org/MPL/

 Software distributed under the License is distributed on an "AS IS"
 basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 License for the specific language governing rights and limitations
 under the License.

 Alternatively, the contents of this file may be used under the terms
 of the GNU Lesser General Public license version 2 or later (LGPL2+),
 in which case the provisions of LGPL License are applicable instead of
 those above.

 For feedback and questions about my Files and Projects please mail me,
 Alexander Matthes (Ziz) , ziz_at_mailbox.org
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../../src/www_tree.h"

extern void unmangle_ansi(char *body, int len, char **body_out, int *body_len, int dopipe);

typedef struct selem *pelem;
typedef struct selem {
	unsigned char digit[8];
	unsigned char digitcount;
	pelem next;
} telem;

pelem parseInsert(char* s)
{
	pelem firstelem=NULL;
	pelem momelem=NULL;
	unsigned char digit[8];
	unsigned char digitcount=0;
	int pos=0;
	for (pos=0;pos<1024;pos++)
	{
		if (s[pos]=='[')
			continue;
		if (s[pos]==';' || s[pos]==0)
		{
			if (digitcount==0)
			{
				digit[0]=0;
				digitcount=1;
			}

			pelem newelem=(pelem)malloc(sizeof(telem));
			for (unsigned char a=0;a<8;a++)
				newelem->digit[a]=digit[a];
			newelem->digitcount=digitcount;
			newelem->next=NULL;
			if (momelem==NULL)
				firstelem=newelem;
			else
				momelem->next=newelem;
			momelem=newelem;
			digitcount=0;
			memset(digit,0,8);
			if (s[pos]==0)
				break;
		}
		else
		if (digitcount<8)
		{
			digit[digitcount]=s[pos]-'0';
			digitcount++;
		}
	}
	return firstelem;
}

void deleteParse(pelem elem)
{
	while (elem!=NULL)
	{
		pelem temp=elem->next;
		free(elem);
		elem=temp;
	}
}

struct www_tag * aha(char *input, struct www_tag *parent, int dopipe)
{
	//Searching Parameters
    char *unmangle_out;
    int unmangle_out_len;
    unmangle_ansi(input, strlen(input), &unmangle_out, &unmangle_out_len, dopipe);

    unmangle_out[unmangle_out_len] = '\0';

	//Begin of Conversion
	unsigned int c;
	int fc = -1; //Standard Foreground Color //IRC-Color+8
	int bc = -1; //Standard Background Color //IRC-Color+8
	int ul = 0; //Not underlined
	int bo = 0; //Not bold
	int bl = 0; //No Blinking
	int ofc,obc,oul,obo,obl; //old values
	int line=0;
	int momline=0;
	int newline=-1;
	int temp;
    char *ptr = unmangle_out;
    int size = 256;
    int outat = 0;
    char minibuf[2];
	struct www_tag *child = NULL;
	stralloc data = EMPTY_STRALLOC;

	while (*ptr != '\0')
	{
        c = *ptr++;
		if (c=='\033')
		{
			//Saving old values
			ofc=fc;
			obc=bc;
			oul=ul;
			obo=bo;
			obl=bl;
			//Searching the end (a letter) and safe the insert:
			c= *ptr++;
            if (c == '\0') {
                return parent;
            }
			if ( c == '[' ) // CSI code, see https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
			{
				char buffer[1024];
				buffer[0] = '[';
				int counter=1;
				while ((c<'A') || ((c>'Z') && (c<'a')) || (c>'z'))
				{
					c=*ptr++;
                    if (c == '\0') {
                        return parent;
                    }
					buffer[counter]=c;
					if (c=='>') //end of htop
						break;
					counter++;
					if (counter>1022)
						break;
				}
				buffer[counter-1]=0;
				pelem elem;
				switch (c)
				{
					case 'm':
						//printf("\n%s\n",buffer); //DEBUG
						elem=parseInsert(buffer);
						pelem momelem=elem;
						while (momelem!=NULL)
						{
							//jump over zeros
							int mompos=0;
							while (mompos<momelem->digitcount && momelem->digit[mompos]==0)
								mompos++;
							if (mompos==momelem->digitcount) //only zeros => delete all
							{
								bo=0;ul=0;bl=0;fc=-1;bc=-1;
							}
							else
							{
								switch (momelem->digit[mompos])
								{
									case 1: if (mompos+1==momelem->digitcount)  // 1, 1X not supported
												bo=1;
											break;
									case 2: if (mompos+1<momelem->digitcount) // 2X, 2 not supported
												switch (momelem->digit[mompos+1])
												{
													case 1: //Reset and double underline (which aha doesn't support)
													case 2: //Reset bold
														bo=0;
														break;
													case 4: //Reset underline
														ul=0;
														break;
													case 5: //Reset blink
														bl=0;
														break;
													case 7: //Reset Inverted
														if (bc == -1)
															bc = 8;
														if (fc == -1)
															fc = 9;
														temp = bc;
														bc = fc;
														fc = temp;
														break;
												}
											break;
									case 3: if (mompos+1<momelem->digitcount)  // 3X, 3 not supported
												fc=momelem->digit[mompos+1];
											break;
									case 4: if (mompos+1==momelem->digitcount)  // 4
												ul=1;
											else // 4X
												bc=momelem->digit[mompos+1];
											break;
									case 5: if (mompos+1==momelem->digitcount) //5, 5X not supported
												bl=1;
											break;
									//6 and 6X not supported at all
									case 7: if (bc == -1) //7, 7X is mot defined (and supported)
												bc = 8;
											if (fc == -1)
												fc = 9;
											temp = bc;
											bc = fc;
											fc = temp;
											break;
									//8 and 9 not supported
								}
							}
							momelem=momelem->next;
						}
						deleteParse(elem);
					break;
				}
				//Checking the differences
				if ((fc!=ofc) || (bc!=obc) || (ul!=oul) || (bo!=obo) || (bl!=obl)) //ANY Change
				{
					if ((fc!=-1) || (bc!=-1) || (ul!=0) || (bo!=0) || (bl!=0))
					{
						if (data.len > 0) {
							stralloc_0(&data);
							struct www_tag *datatag = www_tag_new(NULL, data.s);
							free(data.s);
							data = EMPTY_STRALLOC;
							if (child == NULL) {
								www_tag_add_child(parent, datatag);
							} else {
								www_tag_add_child(child, datatag);
								www_tag_add_child(parent, child);
							}
						}
						child = www_tag_new("span", NULL);

						stralloc output = EMPTY_STRALLOC;
						
						switch (fc)
						{
							case	0: 
                                             if (bo) {
												 stralloc_cats(&output, "color:dimgray;");
                                             } else {
												 stralloc_cats(&output, "color:dimgray;");
                                             }
											 break; //Black
							case	1: 
                                             if (bo) {
												stralloc_cats(&output, "color:#FF8888;");
                                             } else {
 												stralloc_cats(&output, "color:red;");
                                             }
											 break; //Red
							case	2: 
                                             if (bo) {
												 stralloc_cats(&output, "color:lime;");
                                             } else {
   												 stralloc_cats(&output, "color:#00FF00;");
                                             }
											 break; //Green
							case	3: 
                                            if (bo) {
												 stralloc_cats(&output, "color:yellow;");
                                            } else {
												 stralloc_cats(&output, "color:olive;");
                                            }
											 break; //Yellow
							case	4: 
                                            if (bo) {
												 stralloc_cats(&output, "color:#8888FF;");
                                            } else {
                                                 stralloc_cats(&output, "color:#0000FF;");
                                            }
											 break; //Blue
							case	5: 
                                            if (bo) {
												 stralloc_cats(&output, "color:fuchsia;");
                                            } else {
												 stralloc_cats(&output, "color:#FF00FF;");
                                            }
											 break; //Purple
							case	6: 
                                             if (bo) {
												 stralloc_cats(&output, "color:aqua;");
                                             } else {
												 stralloc_cats(&output, "color:#008888;");
                                             }
											 break; //Cyan
							case	7: 
                                            if (bo) {
                                                 stralloc_cats(&output, "color:white;");
                                            } else {
                                                 stralloc_cats(&output, "color:grey;");
                                            }
											 break; //White
							case	8: 
                                             stralloc_cats(&output, "color:black;");
											 break; //Background Colour
							case	9: 
                                             stralloc_cats(&output, "color:white;");
											 break; //Foreground Color
						}
						switch (bc)
						{
							case	0: 
											 stralloc_cats(&output, "background-color:black;");
											 break; //Black
							case	1: 
											 stralloc_cats(&output, "background-color:red;");
											 break; //Red
							case	2: 
                                			 
                                             stralloc_cats(&output, "background-color:lime;");
											 break; //Green
							case	3: 
                                             stralloc_cats(&output, "background-color:yellow;");
											 break; //Yellow
							case	4: 
                                             stralloc_cats(&output, "background-color:#3333FF;");
											 break; //Blue
							case	5: 
                                             stralloc_cats(&output, "background-color:fuchsia;");
											 break; //Purple
							case	6: 
                                             stralloc_cats(&output, "background-color:aqua;");
											 break; //Cyan
							case	7: 
                                             stralloc_cats(&output, "background-color:white;");
											 break; //White
							case	8: 
                                             stralloc_cats(&output, "background-color:black;");
											 break; //Background Colour
							case	9: 
                                             stralloc_cats(&output, "background-color:white;");
											 break; //Foreground Colour
						}
						if (ul)
						{
							stralloc_cats(&output, "text-decoration:underline;");
						}
						if (bl)
						{
							stralloc_cats(&output, "text-decoration:blink;");
						}

                       stralloc_0(&output);
                       www_tag_add_attrib(child, "style", output.s);
                       free(output.s);
					}
				}
			}
		}
		else if (c!=8)
		{
			line++;
			switch (c)
			{

				case '\n':
				case 13: 
					momline++;
				    line=0;
					struct www_tag *brtag = www_tag_new("br", NULL);
					if (data.len > 0) {
						if (child != NULL) {
							stralloc_0(&data);
							struct www_tag *datatag = www_tag_new(NULL, data.s);
							free(data.s);
							data = EMPTY_STRALLOC;				
							www_tag_add_child(child, datatag);
							www_tag_add_child(child, brtag);
							www_tag_add_child(parent, child);
							child = www_tag_duplicate(child);
						} else {
							stralloc_0(&data);
							struct www_tag *datatag = www_tag_new(NULL, data.s);
							free(data.s);
							data = EMPTY_STRALLOC;				
							www_tag_add_child(parent, datatag);
							www_tag_add_child(parent, brtag);							
						}
					} else {

						
						if (child != NULL) {
							www_tag_add_child(child, brtag);
							www_tag_add_child(parent, child);
							child = www_tag_duplicate(child);
							
						} else {
							www_tag_add_child(parent, brtag);
						}
					}
                    break;
				default:	{
                    stralloc_append1(&data, c);
                    break;
                }
			}
		}
	}
	
	if (data.len > 0) {
		stralloc_0(&data);
		struct www_tag *datatag = www_tag_new(NULL, data.s);
		free(data.s);
		data = EMPTY_STRALLOC;
		if (child == NULL) {
			www_tag_add_child(parent, datatag);
		} else {
			www_tag_add_child(child, datatag);
            www_tag_add_child(parent, child);			
		}
	}
	free(unmangle_out);
	return parent;
}
