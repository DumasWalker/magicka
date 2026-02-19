#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char **argv) {
	FILE *fptr1;
	FILE *fptr2;

	char buffer1[1024];
	char buffer2[1024];
	char buffer3[1024];
	int z, x;
	int lineno = 0;

	if (argc < 3) {
		printf("Usage: %s magicka.strings dist/magicka.strings\n", argv[0]);
		exit(-1);
	}

	fptr1 = fopen(argv[2], "r");
	fptr2 = fopen(argv[1], "r");


	if (!fptr1) {
		printf("Unable to open %s\n", argv[2]);
		exit(-1);
	}

	if (!fptr2) {
		printf("Unable to open %s\n", argv[1]);
	}

	while (1) {
		if (feof(fptr1)) {
			break;
		}
		if (feof(fptr2)) {
			printf("%s doesn't have enough lines...\n", argv[1]);
			break;
		}
		printf("LINE %d: ", lineno + 1);
		fgets(buffer1, 1024, fptr1);
		fgets(buffer2, 1024, fptr2);
		memset(buffer3, '\0', 1024);
		z = 0;

		for (int i=0;i<strlen(buffer1);i++) {
			if (buffer1[i] == '%') {
				if (buffer1[i+1] == '%') {
					i++;
					continue;
				}
				while (!isalpha(buffer1[i++]));
				buffer3[z++] = buffer1[i-1];
			}
		}

		x = 0;

		for (int i=0;i<strlen(buffer2);i++) {
			if (buffer2[i] == '%') {
				if (buffer2[i+1] == '%') {
					i++;
					break;;
				}
				while (!isalpha(buffer2[i++]));
				if (z < x) {
					printf("Needs updating! %s\n", buffer3);
					fclose(fptr1);
					fclose(fptr2);
					return -1;		
				}
				if (buffer2[i-1] != buffer3[x++]) {
					printf("Needs updating! %s\n", buffer3);
					fclose(fptr1);
					fclose(fptr2);
					return -1;
				} 
			}
		}

		if (x != z) {
			printf("Needs updating!\n");
			fclose(fptr1);
			fclose(fptr2);
			return -1;			
		}
		lineno++;
		printf("OK %s\n", buffer3);
	}
	fclose(fptr1);
	fclose(fptr2);
}