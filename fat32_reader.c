/***********************************************************
 * Name of program: fat32_reader
 * Authors: Andrew Kaplan
 * Description: A Unix interpreter for the Fat 32 file system
 **********************************************************/

/********************************************************************************************/
/* INCLUDES */
/********************************************************************************************/
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <strings.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <stdint.h>
	#include <unistd.h>
	#include <ctype.h>
/********************************************************************************************/
/* DEFINES */
/********************************************************************************************/
	#define True 1  /* C has no booleans! */
	#define False 0
	#define MAX_CMD 80
	#define BOOT_SECTOR_MAX_BYTES 90
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
	#define ENTRY_DELETED 0x40
	#define ENTRY_IS_LAST 0x00
	#define SHORT_NAME_FIRST_MAX_LENGTH 9
	#define SHORT_NAME_SECOND_MAX_LENGTH 4
	#define SHORT_NAME_FULL_MAX_LENGTH 13
	#define SPACE 0x20
	#define PERIOD 0x2E
	#define NEWLINE 0xA
	#define MAX_ATTR_LEN 83
/********************************************************************************************/
/* STRUCT DEFINITIONS */
/********************************************************************************************/
	typedef struct {
		FILE *img_fp;
		int img_fd;
		unsigned short BPB_BytsPerSec;
		unsigned char BPB_SecPerClus;
		unsigned short BPB_RsvdSecCnt;
		unsigned char BPB_NumFATs;
		unsigned int BPB_FATSz32;
		unsigned int BPB_RootClus;
		unsigned int FirstDataSector;
		unsigned int *FAT_table;
		off_t fat_offset;
	} fatinfo_t;

	typedef struct {
		off_t offset;
		unsigned char *cluster;
	} pwd_t;

	typedef struct {
		off_t offset;
		unsigned int size;
		unsigned int next_clust;
		int first_len;
		int last_len;
		int full_len;
		char first[SHORT_NAME_FIRST_MAX_LENGTH];
		char last[SHORT_NAME_SECOND_MAX_LENGTH];
		char full_name[SHORT_NAME_FULL_MAX_LENGTH];
		unsigned char attr;
	} entry_t;
/********************************************************************************************/
/* GLOBAL DECLARATIONS */
/********************************************************************************************/
	static fatinfo_t fat_info;
	static pwd_t pwd;
	static pwd_t root_dir;
/********************************************************************************************/
/* FUNCTION DECLARATIONS */
/********************************************************************************************/
	/* MAIN FUNCTIONS */
		void display_info();
		void display_ls();
		void display_stat(char *name, char only_size);
		void display_size(char *name);
		void display_volume();
		void do_cd(char *dir_name);
	/* HELPER FUNCTIONS */
		void read_entry(entry_t *entry, unsigned char *buff, int index);
		static unsigned int readLittleEnd(unsigned char *buff, int index, int size);
		unsigned char * read_cluster(off_t offset);
		void get_fullname(char *first, char *last, char *output);
		char * parse_filename_input(char *input, int cmd_len);
		char * get_file_attr_type(unsigned char attr);
	/* STARTUP FUNCTIONS */
		void open_img(char *filename);
		void parse_boot_sector();
		void read_fat();
/********************************************************************************************/
/* MAIN FUNCTIONS */
/********************************************************************************************/
	void display_info(){
		fatinfo_t *fi = &fat_info;
		fprintf(stdout, "BPB_BytsPerSec is 0x%x, %d\n", fi->BPB_BytsPerSec, fi->BPB_BytsPerSec);
		fprintf(stdout, "BPB_SecPerClus is 0x%x, %d\n", fi->BPB_SecPerClus, fi->BPB_SecPerClus);
		fprintf(stdout, "BPB_RsvdSecCnt is 0x%x, %d\n", fi->BPB_RsvdSecCnt, fi->BPB_RsvdSecCnt);
		fprintf(stdout, "BPB_NumFATs is 0x%x, %d\n", fi->BPB_NumFATs, fi->BPB_NumFATs);
		fprintf(stdout, "BPB_FATSz32 is 0x%x, %d\n", fi->BPB_FATSz32, fi->BPB_FATSz32);
		// debugging fprintfs
		fprintf(stdout, "BPB_RootClus is 0x%x, %d\n", fi->BPB_RootClus, fi->BPB_RootClus);
		fprintf(stdout, "FirstDataSector is %x, %d\n", fi->FirstDataSector, fi->FirstDataSector);
		fprintf(stdout, "FatOffset is %lx, %ld\n", fi->fat_offset, fi->fat_offset);
		fprintf(stdout, "RootOffset is %lx, %ld\n", root_dir.offset, root_dir.offset);
		fprintf(stdout, "pwd offset is %lx, %ld\n",pwd.offset, pwd.offset);
	}

	//TODO - enable listing entries located beyond the pwd's starting cluster
	void display_ls(){
		pwd_t *wd = &pwd;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		int i = 0;
		while(True){
			read_entry(entry, wd->cluster, 32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr & ENTRY_DELETED || entry->attr & ATTR_HIDDEN || entry->attr & ATTR_SYSTEM || entry->attr & ATTR_LONG_NAME) continue;
			fprintf(stdout, "%s\t", entry->full_name);
		}
		printf("\n");
		free(entry);
	}

	void display_stat(char *name, char only_size){
		char *input;
		if((input = parse_filename_input(name, 4)) == 0) return;

		pwd_t *wd = &pwd;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		int i = 0;
		while(True){
			read_entry(entry, wd->cluster,32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr & ENTRY_DELETED || entry->attr & ATTR_LONG_NAME) continue;
			if(!strncmp(input, entry->full_name, entry->full_len)){
				char * attrs = get_file_attr_type(entry->attr);
				if(!only_size) fprintf(stdout, "Size is %d\nAttributes %s\nNext cluster number is 0x%x, %d\n",entry->size, attrs, entry->next_clust, entry->next_clust);
				else fprintf(stdout, "Size is %d\n", entry->size);
				free(entry); free(input); free(attrs);
				return;
			}
		}
		fprintf(stderr, "Error: file/directory does not exist\n");
		free(entry); free(input);
	}

	void display_size(char *name){
		display_stat(name, True);
	}

	void display_volume(){
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		pwd_t *wd = &root_dir;
		read_entry(entry, wd->cluster, 0);
		if(entry->first_len > 0) fprintf(stdout, "%s%s\n",entry->first, entry->last);
		else fprintf(stderr, "Error: volume name not found\n");
		free(entry);
	}

	//TODO - enable cd-ing into directories located beyond the pwd's starting cluster
	void do_cd(char *dir_name){
		char *input;
		if((input = parse_filename_input(dir_name, 2)) == 0) return;
		pwd_t *wd = &pwd;
		fatinfo_t *fi = &fat_info;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		int i = 0;
		while(True){
			read_entry(entry, wd->cluster, 32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr & ENTRY_DELETED || entry->attr & ATTR_LONG_NAME || !(entry->attr & ATTR_DIRECTORY)) continue;
			if(!strncmp(input, entry->full_name, entry->full_len)){
				wd->offset = (entry->next_clust == 0x0) ? root_dir.offset: ((entry->next_clust - fi->BPB_RootClus)* fi->BPB_SecPerClus + fi->FirstDataSector) * fi->BPB_BytsPerSec;
				free(wd->cluster); free(entry); free(input);
				wd->cluster = read_cluster(wd->offset);
				return;
			}
		}
		fprintf(stderr, "Error: directory does not exist\n");
		free(entry); free(input);
	}
/********************************************************************************************/
/* HELPER FUNCTIONS */
/********************************************************************************************/
	/** 
	 * Reads the contents of a directory entry and populates a struct of type entry_t
	 * If the entry is the last one in a directory or is otherwise invalid, only the attr
	 * field is filled. The caller must check if the attr field is valid before checking other
	 * fields in the entry_t struct.
	*/
	void read_entry(entry_t *entry, unsigned char *buff, int index){
		if(buff[index] == 0x00){
			entry->attr = ENTRY_IS_LAST;
			return;
		}
		if(buff[index] == 0xE5){
			entry->attr = ENTRY_DELETED;
			return;
		}
		int i, j;
		// I can't guarantee there are no leftovers from a previous entry, so I need to zero out fullname every time :/
		for(i = 0; i < SHORT_NAME_FULL_MAX_LENGTH; i++) entry->full_name[i] = 0;
		// Next two for loops copy the two components of name
		// When 0x20 = " " is encountered, we have reached the end of this component
		for(i = 0; i < 8; i++){
			if(buff[index+i] == SPACE){
				entry->first[i] = 0;
				entry->first_len = i;
				break;
			}
			entry->first[i] = buff[index+i];
		}
		j = 0;
		for(i = 8; i < 11; i++){
			if(buff[index+i] == SPACE){
				entry->last[j] = 0;
				entry->last_len = j;
				break;
			}
			entry->last[j++] = buff[index+i];
		}

		int hi, lo;
		get_fullname(entry->first, entry->last, entry->full_name);
		entry->full_len = (entry->last_len) ? entry->first_len : entry->first_len + entry->last_len + 1;
		entry->size = readLittleEnd(buff, index+28, 4);
		hi = readLittleEnd(buff, index+20, 2);
		lo = readLittleEnd(buff, index+26, 2);
		entry->attr = readLittleEnd(buff, index+11, 1);
		entry->next_clust = (hi << 16) | lo;
	}

	static unsigned int readLittleEnd(unsigned char *buff, int index, int size){
		unsigned int ret, i;
		ret = buff[index];
		for(i = 1; i < size; i++){
			ret += buff[index + i] << (8 * i);
		}
		return ret;
	}

	unsigned char * read_cluster(off_t offset){
		fatinfo_t *fi = &fat_info;
		unsigned char *cluster = (unsigned char *) malloc(fi->BPB_BytsPerSec * fi->BPB_SecPerClus);
		lseek(fi->img_fd, offset, SEEK_SET);
		if(read(fi->img_fd, cluster, fi->BPB_BytsPerSec) < 0) fprintf(stderr, "failed to read file\n");
		return cluster;
	}

	/** 
	 * Concatenates first and last components of a dir/file name into the full name.
	 * If the last component is empty, only the first component is returned
	*/
	void get_fullname(char *first, char *last, char *output){
		int i = 0, j = 0;
		while(first[i] != 0){
			output[i] = first[i];
			i++;
		}
		if(last[0] != 0){
			output[i++] = PERIOD;
			while(last[j] != 0) output[i++] = last[j++];
		}
	}

	/**
	 * Parse file/dir name argument when calling stat, size, cd, ls, mkdir, rmdir
	 * @param input entire command including function call
	 * @param output return value - parsed argument
	*/
	char * parse_filename_input(char *input, int cmd_len){
		char *output = malloc(MAX_CMD); // just allowing for the user to type in nonsense... I already broke the program doing so :)
		if(input[cmd_len] != SPACE){
			fprintf(stderr, "Error: unable to parse args\n");
			free(output);
			return 0;
		}
		// every string will have a \n as its last character
		int i = 0;
		while(input[i+1+cmd_len] != NEWLINE){
			if(i > 11){
				fprintf(stderr, "Error: file/directory name cannot exceed 12 characters\n");
				free(output);
				return 0;
			}
			output[i] = input[i+1+cmd_len];
			// If lowercase, convert to uppercase
			output[i] = toupper(output[i]);
			i++;
		}
		output[i] = 0;
		return output;
	}

	char * get_file_attr_type(unsigned char attr){
		char * attrs = malloc(MAX_ATTR_LEN); // Just allowing for maximum length of the return string
		if(attr & ATTR_READ_ONLY)	strcat(attrs, "ATTR_READ_ONLY");
		if(attr & ATTR_HIDDEN)		strcat(attrs, "ATTR_HIDDEN");
		if(attr & ATTR_SYSTEM)		strcat(attrs, "ATTR_SYSTEM");
		if(attr & ATTR_VOLUME_ID)	strcat(attrs, "ATTR_VOLUME_ID");
		if(attr & ATTR_DIRECTORY)	strcat(attrs, "ATTR_DIRECTORY");
		if(attr & ATTR_ARCHIVE)		strcat(attrs, "ATTR_ARCHIVE");
		return attrs;
	}
/********************************************************************************************/
/* STARTUP FUNCTIONS */
/********************************************************************************************/
	void parse_boot_sector(){
		fatinfo_t *fi = &fat_info;
		pwd_t *wd = &pwd;
		pwd_t *root = &root_dir;
		unsigned char *boot_sector = malloc(BOOT_SECTOR_MAX_BYTES);
		lseek(fi->img_fd, (off_t) 0, SEEK_SET);
		if(read(fi->img_fd, boot_sector, BOOT_SECTOR_MAX_BYTES) < 0) fprintf(stderr, "failed to read file\n");
		fi->BPB_BytsPerSec = readLittleEnd(boot_sector, BPB_BytsPerSec_offset, sizeof(fi->BPB_BytsPerSec));
		fi->BPB_SecPerClus = readLittleEnd(boot_sector, BPB_SecPerClus_offset, sizeof(fi->BPB_SecPerClus));
		fi->BPB_RsvdSecCnt = readLittleEnd(boot_sector, BPB_RsvdSecCnt_offset, sizeof(fi->BPB_RsvdSecCnt));
		fi->BPB_NumFATs = readLittleEnd(boot_sector, BPB_NumFATs_offset, sizeof(fi->BPB_NumFATs));
		fi->BPB_FATSz32 = readLittleEnd(boot_sector, BPB_FATSz32_offset, sizeof(fi->BPB_FATSz32));
		fi->BPB_RootClus = readLittleEnd(boot_sector, BPB_RootClus_offset, sizeof(fi->BPB_RootClus));
		fi->fat_offset = fi->BPB_RsvdSecCnt * fi->BPB_BytsPerSec;
		fi->FirstDataSector = fi->BPB_RsvdSecCnt + fi->BPB_NumFATs * fi->BPB_FATSz32;
		read_fat();
		wd->offset = root->offset = fi->FirstDataSector * fi->BPB_BytsPerSec;
		wd->cluster = read_cluster(fi->FirstDataSector * fi->BPB_BytsPerSec);
		root->cluster = read_cluster(fi->FirstDataSector * fi->BPB_BytsPerSec);
		free(boot_sector);
	}

	void open_img(char *filename){
		fatinfo_t *fi = &fat_info;
		FILE *fp;
		int fd;
		fp = fopen(filename, "rb"); //TODO set to write privileges
		if(fp == NULL){
			fprintf(stderr, "img file not opened\n");
			exit(EXIT_FAILURE);
		}
		fd = fileno(fp);
		fi->img_fp = fp;
		fi->img_fd = fd;
	}

	void read_fat(){
		fatinfo_t *fi = &fat_info;
		unsigned int size = fi->BPB_FATSz32 * fi->BPB_BytsPerSec;
		int length = size / sizeof(unsigned int), UIntsPerSec = fi->BPB_BytsPerSec / sizeof(unsigned int);
		// dummy value here to silence the compiler. read_cluster() will do malloc for us.
		unsigned char * cluster = 0;
		int i, j = 0;
		fi->FAT_table = (unsigned int *) malloc(size);
		/* 
		This is ugly, I know. I only want to have 1 cluster in memory at a time so this monstrosity (beauty because it works) is the result.
		If i = 0 or some multiple of UnsignedIntsPerSec, read in the next cluster. j tracks which cluster to read.
		*/
		for(i = 0; i < length; i++){
			if(i % UIntsPerSec == 0){
				free(cluster);
				cluster = read_cluster(fi->fat_offset + fi->BPB_BytsPerSec * fi->BPB_SecPerClus * j++);
			}
			fi->FAT_table[i] = readLittleEnd(cluster, (i * 4) % (fi->BPB_BytsPerSec * fi->BPB_SecPerClus), sizeof(unsigned int));
		}
		free(cluster);
	}	
/********************************************************************************************/
/* MAIN */
/********************************************************************************************/
	int main(int argc, char *argv[]){
		char cmd_line[MAX_CMD];
		/* Parse args and open our image file */
		open_img(argv[1]);
		/* Parse boot sector and get information */
		parse_boot_sector();
		/* Get root directory address */
		while(True) {
			bzero(cmd_line, MAX_CMD);
			printf("/]");
			if(!fgets(cmd_line,MAX_CMD,stdin))
				fprintf(stderr, "error using fgets\n");

			/* Start comparing input */
			if(strncmp(cmd_line,"info",4)==0) {
				// printf("Going to display info.\n");
				display_info();
			}

			else if(strncmp(cmd_line,"stat",4)==0){
				// printf("Going to display stat.\n");
				display_stat(cmd_line, False);
			}
			
			else if(strncmp(cmd_line,"size",4)==0) {
				// printf("Going to size!\n");
				display_size(cmd_line);
			}

			else if(strncmp(cmd_line,"volume",6)==0){
				display_volume();
			}

			else if(strncmp(cmd_line,"cd",2)==0) {
				// printf("Going to cd!\n");
				do_cd(cmd_line);
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
		if(fclose(fat_info.img_fp) != EOF) fprintf(stderr, "error closing file pointer\n");
		free(fat_info.FAT_table);
		free(pwd.cluster);
		free(root_dir.cluster);
		return 0; /* Success */
	}

