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
	#define ENTRY_DELETED 0xE5
	#define ENTRY_IS_LAST 0x00
	#define ENTRY_INVALID 0x7F
/********************************************************************************************/
/* STRUCT DEFINITIONS */
/********************************************************************************************/
	typedef struct {
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
		off_t root_offset;
		unsigned char *sector;
	} pwd_t;

	typedef struct {
		off_t offset;
		int size;
		int next_clust;
		int first_len;
		int last_len;
		int full_len;
		char first[9];
		char last[4];
		char full_name[13];
		char attr;
	} entry_t;
/********************************************************************************************/
/* GLOBAL DECLARATIONS */
/********************************************************************************************/
	static fatinfo_t fat_info;
	static pwd_t pwd;
/********************************************************************************************/
/* FUNCTION DECLARATIONS */
/********************************************************************************************/
	/* MAIN FUNCTIONS */
		void display_info();
		void display_ls();
		void display_stat(char *name, char only_size);
		void display_size(char *name);
		void display_volume();
	/* HELPER FUNCTIONS */
		void read_entry(entry_t *entry, unsigned char *buff, int index);
		static unsigned int readLittleEnd(unsigned char *buffer, int index, int size);
		void get_fullname(char *first, char *last, char *output);
		void split_into_first_and_last(char *input, char *first, char *last);
		void parse_filename_input(char *input, char *output);
		int is_valid_attr(unsigned char attr);
		char * get_file_attr_type(unsigned char attr);
	/* STARTUP FUNCTIONS */
		void open_img(char *filename);
		void parse_boot_sector();
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
		fprintf(stdout, "RootOffset is %lx, %ld\n", pwd.root_offset, pwd.root_offset);
	}

	void display_ls(){
		pwd_t *wd = &pwd;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		int i = 1;
		while(True){
			read_entry(entry, wd->sector, 32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr == ENTRY_INVALID) continue;
			fprintf(stdout, "%s\t", entry->full_name);
		}
		printf("\n");
		free(entry);
	}

	void display_stat(char *name, char only_size){
		if(name[4] != 0x20){ // Expected input "stat arg" so the space should be at index 4
			fprintf(stderr, "Error: unable to parse args\n");
			return;
		}
		char input[13];
		parse_filename_input(name, input);

		pwd_t *wd = &pwd;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		int i = 0;
		while(True){
			read_entry(entry, wd->sector,32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr == ENTRY_INVALID) continue;
			if(!strncmp(input, entry->full_name, entry->full_len)){
				if(!only_size) fprintf(stdout, "Size is %d\nAttributes %s\nNext cluster number is 0x%x\n",entry->size, get_file_attr_type(entry->attr), entry->next_clust);
				else fprintf(stdout, "Size is %d\n", entry->size);
				free(entry);
				return;
			}
		}
		fprintf(stderr, "Error: file/directory does not exist\n");
		free(entry);
	}

	void display_size(char *name){
		display_stat(name, True);
	}

	void display_volume(){
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		pwd_t *wd = &pwd;
		read_entry(entry, wd->sector, 0);
		if(entry->first_len > 0) fprintf(stdout, "%s%s\n",entry->first, entry->last);
		else fprintf(stderr, "Error: volume name not found");
		free(entry);
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
		if(buff[index] == 0xE5 || !is_valid_attr(buff[index+11]) || buff[index+11] == ATTR_LONG_NAME){
			entry->attr = ENTRY_INVALID;
			return;
		}
		int i, j;
		// I can't guarantee there are no leftovers from a previous entry, so I need to zero out fullname every time :/
		for(i = 0; i < 13; i++) entry->full_name[i] = 0;
		// Next two for loops copy the two components of name
		for(i = 0; i < 8; i++){
			if(buff[index+i] == 0x20){
				entry->first[i] = 0;
				entry->first_len = i;
				break;
			}
			entry->first[i] = buff[index+i];
		}
		j = 0;
		for(i = 8; i < 11; i++){
			if(buff[index+i] == 0x20){
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

	unsigned char * read_sector(off_t offset){
		fatinfo_t *fi = &fat_info;
		unsigned char *sector = malloc(sizeof(unsigned char) * fi->BPB_BytsPerSec);
		lseek(fi->img_fd, offset, SEEK_SET);
		if(read(fi->img_fd, sector, fi->BPB_BytsPerSec) < 0) fprintf(stderr, "failed to read file");
		return sector;
	}

	void read_fat(){
		fatinfo_t *fi = &fat_info;
		unsigned int size = fi->BPB_FATSz32 * fi->BPB_BytsPerSec;
		int length = size / sizeof(unsigned int), UIntsPerSec = fi->BPB_BytsPerSec / sizeof(unsigned int);
		unsigned char * sector = malloc(fi->BPB_BytsPerSec);
		int i, j = 0;
		fi->FAT_table = (unsigned int *) malloc(size);
		/* 
		This is ugly, I know. I only want to have 1 sector in memory at a time so this monstrosity is the result.
		If i = 0 or some multiple of UnsignedIntsPerSec, read in the next cluster. j tracks which cluster to add.
		We determine which index to read the same way as determining which sector.
		*/
		for(i = 0; i < length; i++){
			if(i % UIntsPerSec == 0){
				sector = read_sector(fi->fat_offset + fi->BPB_BytsPerSec * j++);
			}
			fi->FAT_table[i] = readLittleEnd(sector, (i * 4) % fi->BPB_BytsPerSec, sizeof(unsigned int));
		}
		free(sector);
	}

	static unsigned int readLittleEnd(unsigned char *buffer, int index, int size){
		unsigned int ret, i;
		ret = buffer[index];
		for(i = 1; i < size; i++){
			ret += buffer[index + i] << (8 * i);
		}
		return ret;
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
			output[i++] = 0x2E;
			while(last[j] != 0) output[i++] = last[j++];
		}
	}

	void split_into_first_and_last(char *input, char *first, char *last){
		// Read input up to the period to be recorded in first
		int i = 0, j;
		while(input[i] != 0 && input[i] != 0x2E){
			first[i] = input[i];
			i++;
		}
		first[i] = 0;
		// If the loop terminated because the null character was reached, there is no file extension
		if(input[i] == 0){
			last[0] = 0;
		}
		else{
			i++;
			j = 0;
			while(input[i] != 0){
				last[j++] = input[i];
				i++;
			}
			last[j] = 0;
		}
	}

	/**
	 * Parse file/dir name argument when calling stat, size, cd, ls, mkdir, rmdir
	 * @param input entire command including function call
	 * @param output return value - parsed argument
	*/
	void parse_filename_input(char *input, char *output){
		// every string will have a \n as its last character
		int i = 0;
		while(input[i+5] != 0xA){
			if(i > 11){
				fprintf(stderr, "Error: file/directory name cannot exceed 12 characters\n");
				return;
			}
			output[i] = input[i+5];
			// If lowercase, convert to uppercase
			output[i] = toupper(output[i]);
			i++;
		}
		output[i] = 0;
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
/********************************************************************************************/
/* STARTUP FUNCTIONS */
/********************************************************************************************/
	void parse_boot_sector(){
		fatinfo_t *fi = &fat_info;
		pwd_t *wd = &pwd;
		unsigned char *boot_sector = malloc(sizeof(unsigned char) * 90);
		lseek(fi->img_fd, (off_t) 0, SEEK_SET);
		if(read(fi->img_fd, boot_sector, 90) < 0) fprintf(stderr, "failed to read file");
		fi->BPB_BytsPerSec = readLittleEnd(boot_sector, BPB_BytsPerSec_offset, sizeof(fi->BPB_BytsPerSec));
		fi->BPB_SecPerClus = readLittleEnd(boot_sector, BPB_SecPerClus_offset, sizeof(fi->BPB_SecPerClus));
		fi->BPB_RsvdSecCnt = readLittleEnd(boot_sector, BPB_RsvdSecCnt_offset, sizeof(fi->BPB_RsvdSecCnt));
		fi->BPB_NumFATs = readLittleEnd(boot_sector, BPB_NumFATs_offset, sizeof(fi->BPB_NumFATs));
		fi->BPB_FATSz32 = readLittleEnd(boot_sector, BPB_FATSz32_offset, sizeof(fi->BPB_FATSz32));
		fi->BPB_RootClus = readLittleEnd(boot_sector, BPB_RootClus_offset, sizeof(fi->BPB_RootClus));
		fi->fat_offset = fi->BPB_RsvdSecCnt * fi->BPB_BytsPerSec;
		fi->FirstDataSector = fi->BPB_RsvdSecCnt + fi->BPB_NumFATs * fi->BPB_FATSz32;
		read_fat();
		wd->offset = fi->FirstDataSector * fi->BPB_BytsPerSec;
		wd->root_offset = wd->offset;
		wd->sector = read_sector(fi->FirstDataSector * fi->BPB_BytsPerSec);
	}

	void open_img(char *filename){
		fatinfo_t *fi = &fat_info;
		FILE *fp;
		int fd;
		fp = fopen(filename, "rb"); //TODO set to write privileges
		if(fp == NULL){
			fprintf(stderr, "img file not opened");
			exit(EXIT_FAILURE);
		}
		fd = fileno(fp);
		fi->img_fd = fd;
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
				fprintf(stderr, "error using fgets");

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

