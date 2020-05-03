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
		off_t fat_offset;
	} fatinfo_t;

	typedef struct {
		off_t offset;
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
		void info();
		void display_stat(char *name);
		void display_ls();
	/* HELPER FUNCTIONS */
		void read_entry(entry_t *entry, off_t offset);
		unsigned int read_attr(int fd, off_t offset, int size);
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
	void info(){
		fatinfo_t *fi = &fat_info;
		fprintf(stdout, "BPB_BytsPerSec is 0x%x, %d\n", fi->BPB_BytsPerSec, fi->BPB_BytsPerSec);
		fprintf(stdout, "BPB_SecPerClus is 0x%x, %d\n", fi->BPB_SecPerClus, fi->BPB_SecPerClus);
		fprintf(stdout, "BPB_RsvdSecCnt is 0x%x, %d\n", fi->BPB_RsvdSecCnt, fi->BPB_RsvdSecCnt);
		fprintf(stdout, "BPB_NumFATs is 0x%x, %d\n", fi->BPB_NumFATs, fi->BPB_NumFATs);
		fprintf(stdout, "BPB_FATSz32 is 0x%x, %d\n", fi->BPB_FATSz32, fi->BPB_FATSz32);
	}

	void display_stat(char *name){
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
			read_entry(entry, wd->offset + 32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr == ENTRY_INVALID) continue;
			if(!strncmp(input, entry->full_name, entry->full_len)){
				fprintf(stdout, "Size is %d\nAttributes %s\nNext cluster number is 0x%x\n",entry->size, get_file_attr_type(entry->attr), entry->next_clust);
				free(entry);
				return;
			}
		}
		fprintf(stderr, "Error: file/directory does not exist\n");
		free(entry);
	}

	void display_ls(){
		pwd_t *wd = &pwd;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		int i = 1;
		while(True){
			read_entry(entry, wd->offset + 32 * i++);
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr == ENTRY_INVALID) continue;
			fprintf(stdout, "%s\t", entry->full_name);
		}
		printf("\n");
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
	void read_entry(entry_t *entry, off_t offset){
		fatinfo_t *fi = &fat_info;
		char buff[12];
		lseek(fi->img_fd, offset, SEEK_SET);
		if(read(fi->img_fd, buff, 12) < 0) fprintf(stderr, "failed to read file");
		if(buff[0] == 0x00){
			entry->attr = ENTRY_IS_LAST;
			return;
		}
		if(buff[0] == 0xE5 || !is_valid_attr(buff[11]) || buff[11] == ATTR_LONG_NAME){
			entry->attr = ENTRY_INVALID;
			return;
		}
		int k, j;
		// I can't guarantee there are no leftovers from a previous entry, so I need to zero out fullname every time :/
		for(k = 0; k < 13; k++) entry->full_name[k] = 0;
		k = 3;
		entry->last[k--] = 0;
		for(j = 10; j >= 7; j--) entry->last[k--] = (buff[j] == 0x20) ? 0 : buff[j];
		k = 7;
		entry->first[k--] = 0;
		for(; j >= 0; j--) entry->first[k--] = (buff[j] == 0x20) ? 0 : buff[j];
		// find the length of the comp strings
		j = k = entry->first_len = entry->last_len = 0;
		while(entry->first[j++] != 0) entry->first_len++;
		while(entry->last[k++] != 0) entry->last_len++;

		int hi, lo;
		get_fullname(entry->first, entry->last, entry->full_name);
		entry->full_len = (entry->last_len) ? entry->first_len : entry->first_len + entry->last_len + 1;
		entry->size = read_attr(fi->img_fd, offset+28, 4);
		hi = read_attr(fi->img_fd, offset+20, 2);
		lo = read_attr(fi->img_fd, offset+26, 2);
		entry->attr = read_attr(fi->img_fd, offset+11, 1);
		entry->next_clust = (hi << 2) | lo;
	}

	/** 
	 * Read an attribute of given size in endian neutral way
	*/
	unsigned int read_attr(int fd, off_t offset, int size){
		unsigned int ret;
		int i;
		unsigned char buffer[size];
		lseek(fd, offset, SEEK_SET);
		if(read(fd, buffer, size) < 0) fprintf(stderr, "failed to read file");
		ret = buffer[0];
		for(i = 1; i < size; i++){
			ret += buffer[i] << (8 * i);
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
			if(output[i] >= 0x61 && output[i] <= 0x7A){
				output[i] = output[i] - 0x20;
			}
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
		fi->BPB_BytsPerSec = read_attr(fi->img_fd, BPB_BytsPerSec_offset, sizeof(fi->BPB_BytsPerSec));
		fi->BPB_SecPerClus = read_attr(fi->img_fd, BPB_SecPerClus_offset, sizeof(fi->BPB_SecPerClus));
		fi->BPB_RsvdSecCnt = read_attr(fi->img_fd, BPB_RsvdSecCnt_offset, sizeof(fi->BPB_RsvdSecCnt));
		fi->BPB_NumFATs = read_attr(fi->img_fd, BPB_NumFATs_offset, sizeof(fi->BPB_NumFATs));
		fi->BPB_FATSz32 = read_attr(fi->img_fd, BPB_FATSz32_offset, sizeof(fi->BPB_FATSz32));
		fi->BPB_RootClus = read_attr(fi->img_fd, BPB_RootClus_offset, sizeof(fi->BPB_RootClus));
		fi->fat_offset = fi->BPB_RsvdSecCnt * fi->BPB_BytsPerSec;
		wd->offset = (fi->BPB_RsvdSecCnt + fi->BPB_NumFATs * fi->BPB_FATSz32) * fi->BPB_BytsPerSec;
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

