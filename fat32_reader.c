/***********************************************************
 * Name of program: fat32_reader
 * Authors: Andrew Kaplan
 * Description: A Linux interpreter for the Fat 32 file system
 **********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

/* Put any symbolic constants (defines) here */
#define True 1  /* C has no booleans! */
#define False 0

#define MAX_CMD 80
#define BPB_BytsPerSec_offset 11
#define BPB_SecPerClus_offset 13
#define BPB_RsvdSecCnt_offset 14
#define BPB_NumFATs_offset 16
#define BPB_FATSz32_offset 36
#define BPB_RootClus_offset 44
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define ATTR_LONG_NAME 0x0F

typedef struct {
	int img_fd;
	unsigned short BPB_BytsPerSec;
	unsigned char BPB_SecPerClus;
	unsigned short BPB_RsvdSecCnt;
	unsigned char BPB_NumFATs;
	unsigned int BPB_FATSz32;
	unsigned int BPB_RootClus;
	off_t fat_offset;
} fatinfo_t;

typedef struct {
	off_t offset;
} pwd_t;

static fatinfo_t fat_info;
static pwd_t pwd;

void open_img(char *filename);
void parse_boot_sector();
unsigned int read_attr(int fd, off_t offset, int size);
void info();
void display_stat(char *name);
void display_ls();
char * get_file_attr_type(unsigned char attr);
int is_valid_attr(unsigned char attr);
// void ls();

void info(){
	fatinfo_t *fi = &fat_info;
	printf("BPB_BytsPerSec is 0x%x, %d\n", fi->BPB_BytsPerSec, fi->BPB_BytsPerSec);
	printf("BPB_SecPerClus is 0x%x, %d\n", fi->BPB_SecPerClus, fi->BPB_SecPerClus);
	printf("BPB_RsvdSecCnt is 0x%x, %d\n", fi->BPB_RsvdSecCnt, fi->BPB_RsvdSecCnt);
	printf("BPB_NumFATs is 0x%x, %d\n", fi->BPB_NumFATs, fi->BPB_NumFATs);
	printf("BPB_FATSz32 is 0x%x, %d\n", fi->BPB_FATSz32, fi->BPB_FATSz32);
	// printf("BPB_RootClus is 0x%x, %d\n", fi->BPB_RootClus, fi->BPB_RootClus);
	// printf("fat_offset is 0x%lx, %ld\n", fi->fat_offset, fi->fat_offset);
	// printf("pwd offset is 0x%lx, %ld\n", pwd.offset, pwd.offset);
}

void display_stat(char *name){
	fatinfo_t *fi = &fat_info;
	pwd_t *wd = &pwd;
	unsigned char dir_name[8];
	unsigned char attr;
	unsigned short first_clust;
	unsigned int file_size;
	lseek(fi->img_fd, wd->offset, SEEK_SET);
	if(read(fi->img_fd, dir_name, 8) < 0) perror("failed to read file");
	attr = read_attr(fi->img_fd, wd->offset + 11, 1);
	first_clust = read_attr(fi->img_fd, wd->offset + 26, 2);
	file_size = read_attr(fi->img_fd, wd->offset + 28, 4);
	printf("Name is %s\n", dir_name);
	printf("Size is %d\n",file_size);
	printf("Attributes %s\n", get_file_attr_type(attr));
	printf("Next cluster number is 0x%x\n", first_clust);
}

void display_ls(){
	fatinfo_t *fi = &fat_info;
	pwd_t *wd = &pwd;
	unsigned char buff[12];
	unsigned char first[9];
	unsigned char last[4];
	int i = 1, j, k;
	do {
		lseek(fi->img_fd, wd->offset + 32 * i++, SEEK_SET); // Advance 1 directory entry
		if(read(fi->img_fd, buff, 12) < 0) perror("failed to read file"); // Read 11 name bytes + 1 attr byte
		if(buff[0] == 0x00) break;
		if(buff[0] == 0xE5 || !is_valid_attr(buff[11]) || buff[11] == ATTR_LONG_NAME) continue;
		// This part is to isolate the first 8 and last 3 bytes of the 11 name bytes and eliminate any trailing spaces
		k = 3;
		last[k--] = 0;
		for(j = 10; j >= 7; j--) last[k--] = (buff[j] == 0x20) ? 0 : buff[j];
		k = 7;
		first[k--] = 0;
		for(; j >= 0; j--) first[k--] = (buff[j] == 0x20) ? 0 : buff[j];
		if(last[0] == 0) printf("%s\t",first);
		else printf("%s.%s\t",first, last);
	} while(True);
	printf("\n");
}

void open_img(char *filename){
	fatinfo_t *fi = &fat_info;
	FILE *fp;
	int fd;
	fp = fopen(filename, "rb"); //TODO set to write privileges
	if(fp == NULL){
		perror("img file not opened");
		exit(EXIT_FAILURE);
	}
	fd = fileno(fp);
	fi->img_fd = fd;
}

char * get_file_attr_type(unsigned char attr){
	switch (attr)
	{
	case ATTR_READ_ONLY:
		return "ATTR_READ_ONLY";
	case ATTR_HIDDEN:
		return "ATTR_HIDDEN";
	case ATTR_SYSTEM:
		return "ATTR_SYSTEM";
	case ATTR_VOLUME_ID:
		return "ATTR_VOLUME_ID";
	case ATTR_DIRECTORY:
		return "ATTR_DIRECTORY";
	case ATTR_ARCHIVE:
		return "ATTR_ARCHIVE";
	default:
		return NULL;
		break;
	}
}

int is_valid_attr(unsigned char attr){
		switch (attr)
	{
	case ATTR_READ_ONLY:
	case ATTR_HIDDEN:
	case ATTR_SYSTEM:
	case ATTR_VOLUME_ID:
	case ATTR_DIRECTORY:
	case ATTR_ARCHIVE:
	case ATTR_LONG_NAME:
		return True;
	default:
		return False;
		break;
	}
}

void parse_boot_sector(){
	fatinfo_t *fi = &fat_info;
	pwd_t *wd = &pwd;
	fi->BPB_BytsPerSec = read_attr(fi->img_fd, BPB_BytsPerSec_offset, sizeof(fi->BPB_BytsPerSec));
	fi->BPB_SecPerClus = read_attr(fi->img_fd, BPB_SecPerClus_offset, sizeof(fi->BPB_SecPerClus));
	fi->BPB_RsvdSecCnt = read_attr(fi->img_fd, BPB_RsvdSecCnt_offset, sizeof(fi->BPB_RsvdSecCnt));
	fi->BPB_NumFATs = read_attr(fi->img_fd, BPB_NumFATs_offset, sizeof(fi->BPB_NumFATs));
	fi->BPB_FATSz32 = read_attr(fi->img_fd, BPB_FATSz32_offset, sizeof(fi->BPB_FATSz32));
	fi->BPB_RootClus = read_attr(fi->img_fd, BPB_RootClus_offset, sizeof(fi->BPB_RootClus));
	fi->fat_offset = fi->BPB_RsvdSecCnt * fi->BPB_BytsPerSec;
	wd->offset = (fi->BPB_RsvdSecCnt + fi->BPB_NumFATs * fi->BPB_FATSz32) * fi->BPB_BytsPerSec;
}

unsigned int read_attr(int fd, off_t offset, int size){
	unsigned int ret;
	int i;
	unsigned char buffer[size];
	lseek(fd, offset, SEEK_SET);
	if(read(fd, buffer, size) < 0) perror("failed to read file");
	ret = buffer[0];
	for(i = 1; i < size; i++){
		ret += buffer[i] << (8 * i);
	}
	return ret;
}

/* This is the main function of your project, and it will be run
 * first before all other functions.
 */
int main(int argc, char *argv[])
{
	char cmd_line[MAX_CMD];

	/* Parse args and open our image file */
	open_img(argv[1]);
	/* Parse boot sector and get information */
	parse_boot_sector();
	/* Get root directory address */
	//printf("Root addr is 0x%x\n", root_addr);


	/* Main loop.  You probably want to create a helper function
       for each command besides quit. */

	while(True) {
		bzero(cmd_line, MAX_CMD);
		printf("/]");
		if(!fgets(cmd_line,MAX_CMD,stdin))
			fprintf(stderr, "error using fgets");

		/* Start comparing input */
		if(strncmp(cmd_line,"info",4)==0) {
			// printf("Going to display info.\n");
			info();
		}

		else if(strncmp(cmd_line,"stat",4)==0){
			// printf("Going to display stat.\n");
			display_stat(cmd_line);
		}

		else if(strncmp(cmd_line,"open",4)==0) {
			printf("Going to open!\n");
		}

		else if(strncmp(cmd_line,"close",5)==0) {
			printf("Going to close!\n");
		}
		
		else if(strncmp(cmd_line,"size",4)==0) {
			printf("Going to size!\n");
		}

		else if(strncmp(cmd_line,"cd",2)==0) {
			printf("Going to cd!\n");
		}

		else if(strncmp(cmd_line,"ls",2)==0) {
			// printf("Going to ls.\n");
			display_ls();
		}

		else if(strncmp(cmd_line,"read",4)==0) {
			printf("Going to read!\n");
		}
		
		else if(strncmp(cmd_line,"quit",4)==0) {
			printf("Quitting.\n");
			break;
		}
		else
			printf("Unrecognized command.\n");


	}

	/* Close the file */
	close(fat_info.img_fd);
	return 0; /* Success */
}

