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
	#define DELETE 0xE5
	#define SHORT_NAME_FIRST_MAX_LENGTH 9
	#define SHORT_NAME_SECOND_MAX_LENGTH 4
	#define SHORT_NAME_FULL_MAX_LENGTH 13
	#define SPACE 0x20
	#define PERIOD 0x2E
	#define NEWLINE 0xA
	#define MAX_ATTR_LEN 83
	#define EOC 0x0FFFFFFF
	#define EOC2 0x0FFFFFF8
	#define BAD 0x0FFFFFF7
	#define LS 0x01
	#define CD 0x02
	#define STAT 0x04
	#define SIZE 0x08
	#define READ 0x10
	#define RMDIR 0x20
	#define MKDIR 0x40
	#define FIRST_USER_DEFINED_ENTRY_SPACE_OFFSET 64
	#define HI_MASK 0xFFFF0000U
	#define LO_MASK 0x0000FFFFU
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
		unsigned int first_clust_num;
		unsigned char *cluster;
	} pwd_t;

	typedef struct {
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
		void do_ls_cd_stat_size_read_rmdir_mkdir(char *name, unsigned int routine);
		void display_volume();
		void read_file(entry_t *entry, unsigned int position, unsigned int num_bytes);
		void do_rmdir(entry_t *entry, off_t entry_offset);
		void do_mkdir(char *dir_name, off_t entry_offset);
	/* HELPER FUNCTIONS */
		void read_entry(entry_t *entry, unsigned char *buff, int index);
		static unsigned int readLittleEnd(unsigned char *buff, int index, int size);
		void writeLittleEnd(unsigned char *out, unsigned int in, int size);
		unsigned char * read_cluster(off_t offset);
		void get_fullname(char *first, char *last, char *output);
		char * parse_filename_input(char *input, int cmd_len, char last_char);
		char * get_file_attr_type(unsigned char attr);
		off_t get_cluster_offset(int clust_num);
		void parse_pos_and_num_bytes(char *input, unsigned int *position, unsigned int *num_bytes);
		unsigned int find_unallocated_clust();
		unsigned char * make_entry(char *name, unsigned int clust);
		void update_fat(unsigned int clust, unsigned int next_clust);
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
		// fprintf(stdout, "BPB_RootClus is 0x%x, %d\n", fi->BPB_RootClus, fi->BPB_RootClus);
		// fprintf(stdout, "FirstDataSector is %x, %d\n", fi->FirstDataSector, fi->FirstDataSector);
		// fprintf(stdout, "FatOffset is %lx, %ld\n", fi->fat_offset, fi->fat_offset);
		// fprintf(stdout, "RootOffset is %lx, %ld\n", root_dir.offset, root_dir.offset);
		// fprintf(stdout, "pwd offset is %lx, %ld\n",pwd.offset, pwd.offset);
	}

	/** 
	 * I realized that each of these functions have the same overall structure, with only slight variations.
	 * Now we have 6 functions in one where the variations are accounted for using the
	 * @param routine - bitmask, where each routine is assigned a bit and associated with said bit by a symbolic constant bearing its name.
	*/
	void do_ls_cd_stat_size_read_rmdir_mkdir(char *name, unsigned int routine){
		pwd_t *wd = &pwd;
		fatinfo_t *fi = &fat_info;
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		char *input = 0, success = False;
		unsigned int position, num_bytes; // need these if doing read
		position = num_bytes = 0; // silence the compiler
		if((routine & STAT || routine & SIZE) && (input = parse_filename_input(name, 4, NEWLINE)) == 0) return;
		if(routine & CD && (input = parse_filename_input(name, 2, NEWLINE)) == 0) return;
		if((routine & RMDIR || routine & MKDIR) && (input = parse_filename_input(name, 5, NEWLINE)) == 0) return;
		if(routine & READ && (input = parse_filename_input(name, 4, SPACE)) == 0) return;
		if(routine & READ) parse_pos_and_num_bytes(name, &position, &num_bytes);
		int i = 0, j = 0, this_clust_offset,
		entriesPerClus = (fi->BPB_BytsPerSec * fi->BPB_SecPerClus) / 32;
		unsigned int thisClus = wd->first_clust_num;
		off_t next_clus_offset = get_cluster_offset(thisClus);
		while(True){
			if(j != 0 && j % entriesPerClus == 0){ // We only want to read in another cluster if we've reached the end of at least 1
				thisClus = fi->FAT_table[thisClus];
				if(thisClus == EOC || thisClus == EOC2 || thisClus == BAD) break;
				free(wd->cluster);
				next_clus_offset = get_cluster_offset(thisClus);
				wd->cluster = read_cluster(next_clus_offset);
				i = 0;
			} j++;
			this_clust_offset = 32 * i++;
			read_entry(entry, wd->cluster, this_clust_offset);
			if(routine & MKDIR && (entry->attr & ENTRY_IS_LAST || entry->attr & ENTRY_DELETED)){
				do_mkdir(input, next_clus_offset + this_clust_offset);
				END_LOOP:
				free(input);
				success = True;
				break;
			}
			if(entry->attr == ENTRY_IS_LAST) break;
			if(entry->attr & ENTRY_DELETED || entry->attr & ATTR_LONG_NAME) continue;
			if(routine & LS && !(entry->attr & ATTR_HIDDEN) && !(entry->attr & ATTR_SYSTEM)){
				fprintf(stdout, "%s\t", entry->full_name);
			}
			if((routine & STAT || routine & SIZE) && !strncmp(input, entry->full_name, entry->full_len)){
				char * attrs = get_file_attr_type(entry->attr);
				if(routine & STAT) fprintf(stdout, "Size is %d\nAttributes %s\nNext cluster number is 0x%x, %d\n",entry->size, attrs, entry->next_clust, entry->next_clust);
				else fprintf(stdout, "Size is %d\n", entry->size);
				free(attrs);
				goto END_LOOP;
			}
			if(routine & CD && !strncmp(input, entry->full_name, entry->full_len)){
				wd->offset = get_cluster_offset(entry->next_clust);
				wd->first_clust_num = entry->next_clust;
				free(wd->cluster);
				wd->cluster = read_cluster(wd->offset);
				goto END_LOOP;
			}
			if(routine & READ && !strncmp(input, entry->full_name, entry->full_len)){
				read_file(entry, position, num_bytes);
				goto END_LOOP;
			}
			if(routine & RMDIR && !strncmp(input, entry->full_name, entry->full_len)){
				do_rmdir(entry, next_clus_offset + this_clust_offset);
				goto END_LOOP;
			}
		}
		free(entry);
		if(!success && !(routine & LS) && !(routine & MKDIR)) fprintf(stderr, "Error: file/directory does not exist\n");
		else if(routine & LS) fprintf(stdout, "\n");
		else if(routine & MKDIR && success == False) fprintf(stderr, "Error, no more space allocated in pwd to make directory.\n");
		// Make sure when we're done to reset pwd cluster to first cluster.
		if(!(thisClus == wd->first_clust_num)){
			free(wd->cluster);
			next_clus_offset = get_cluster_offset(wd->first_clust_num);
			wd->cluster = read_cluster(next_clus_offset);
		}
	}

	void display_volume(){
		entry_t *entry = (entry_t*) malloc(sizeof(entry_t));
		pwd_t *wd = &root_dir;
		read_entry(entry, wd->cluster, 0);
		if(entry->first_len > 0) fprintf(stdout, "%s%s\n",entry->first, entry->last);
		else fprintf(stderr, "Error: volume name not found\n");
		free(entry);
	}

	void read_file(entry_t *entry, unsigned int position, unsigned int num_bytes){
		if((position + num_bytes - 1) > entry->size){
			fprintf(stderr, "Read error: specified segment beyond file boundary.\n");
			return;
		}
		fatinfo_t *fi = &fat_info;
		off_t disk_offset;
		int clust_num = position / (fi->BPB_BytsPerSec * fi->BPB_SecPerClus);
		int clust_offset = position % (fi->BPB_BytsPerSec * fi->BPB_SecPerClus);
		int i;
		unsigned int thisClus = entry->next_clust;
		unsigned char *cluster;
		// if the read does not start in the first cluster, walk the FAT table to the cluster it does start at
		for(i = 0; i < clust_num; i++){
			thisClus = fi->FAT_table[thisClus];
			if(thisClus == EOC || thisClus == EOC2 || thisClus == BAD){
				fprintf(stderr, "Read error: file corrupted.\n");
				return;
			}
		}
		unsigned char *output = malloc(num_bytes);
		disk_offset = get_cluster_offset(thisClus);
		cluster = read_cluster(disk_offset);
		/* 
			This is to fill the output buffer with num_bytes bytes in the specified file.
			If clust_offset is equal to the size of a cluster, walk the FAT table to the next
			allocated cluster for the file and read it in, resetting clust_offset to 0.
		*/
		for(i = 0; i < num_bytes; i++){
			output[i] = cluster[clust_offset++];
			if(clust_offset == fi->BPB_BytsPerSec * fi->BPB_SecPerClus){
				thisClus = fi->FAT_table[thisClus];
				if(thisClus == EOC || thisClus == EOC2 || thisClus == BAD){
					fprintf(stderr, "Read error: file corrupted.\n");
					free(output); free(cluster);
					return;
				}
				disk_offset = get_cluster_offset(thisClus);
				free(cluster);
				cluster = read_cluster(disk_offset);
				clust_offset = 0;
			}
		}
		fprintf(stdout, "%s\n", output);
		free(output); free(cluster);
	}

	/** 
	 * Set first byte of entry to 0xE5 (entry deleted) is entry is a directory and is empty.
	 * If entry is in the first cluster of its parent DIR, changes show up after calling ls twice (not sure why)
	 * @param entry - entry to be deleted
	 * @param entry_offset - disk offset of entry to be deleted
	*/
	void do_rmdir(entry_t *entry, off_t entry_offset){
		if(!(entry->attr & ATTR_DIRECTORY)){
			fprintf(stderr, "Specified file is not a directory\n");
			return;
		}
		fatinfo_t *fi = &fat_info;
		off_t offset = get_cluster_offset(entry->next_clust);
		unsigned char *cluster = read_cluster(offset);
		if(cluster[FIRST_USER_DEFINED_ENTRY_SPACE_OFFSET] != ENTRY_IS_LAST){
			fprintf(stderr, "Error: specified directory is not empty\n");
			free(cluster);
			return;
		}
		fseek(fi->img_fp, entry_offset, SEEK_SET);
		if(fputc(DELETE, fi->img_fp) == EOF){
			fprintf(stderr, "Error writing directory deletion to disk.\n");
		}
		// If I remove the following line, rmdir doesn't work. I think the reason is because calling fseek forces the OS to write cached
		// changes to disk?
		fseek(fi->img_fp, entry_offset, SEEK_SET);
		free(cluster);
		return;
	}

	/** 
	 * Search the FAT table for an unallocated cluster and assign that cluster
	 * Write dir in that spot.
	 * Go to the allocated cluster and make . & .. entries
	*/
	void do_mkdir(char *dir_name, off_t entry_offset){
		fatinfo_t *fi = &fat_info;
		pwd_t *wd = &pwd;
		unsigned int clust = find_unallocated_clust();
		unsigned char *new_entry = make_entry(dir_name, clust);
		unsigned char *dot = make_entry(".", clust);
		unsigned char *dotdot = make_entry("..", wd->first_clust_num);
		off_t new_entry_offset = get_cluster_offset(clust);
		fseek(fi->img_fp, entry_offset, SEEK_SET);
		fwrite(new_entry, 1, 32, fi->img_fp);
		fseek(fi->img_fp, new_entry_offset, SEEK_SET);
		fwrite(dot, 1, 32, fi->img_fp);
		fwrite(dotdot, 1, 32, fi->img_fp);
		update_fat(clust, EOC);
		fseek(fi->img_fp, wd->offset, SEEK_SET);
		free(new_entry); free(dot); free(dotdot);
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

	/** 
	 * Reads buffer starting at index total size bytes in little endian.
	*/
	static unsigned int readLittleEnd(unsigned char *buff, int index, int size){
		unsigned int ret, i;
		ret = buff[index];
		for(i = 1; i < size; i++){
			ret += buff[index + i] << (8 * i);
		}
		return ret;
	}

	/** 
	 * Writes @param size bytes of @param in to buffer @param out in little endian.
	*/
	void writeLittleEnd(unsigned char *out, unsigned int in, int size){
		int i;
		for(i = 0; i < size; i++){
			out[i] = in & 0xFFU;
			in = in >> 8;
		}
	}

	/** 
	 * Reads cluster at @param offset on disk and returns a byte array of Cluster Size
	*/
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
	char * parse_filename_input(char *input, int cmd_len, char last_char){
		char *output = malloc(MAX_CMD); // just allowing for the user to type in nonsense... I already broke the program doing so :)
		if(input[cmd_len] != SPACE){
			fprintf(stderr, "Error: unable to parse args\n");
			free(output);
			return 0;
		}
		// every string will have a \n as its last character
		int i = 0;
		while(input[i+1+cmd_len] != last_char){
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

	/**
	 * Helper function for read. Given command line input, parses @param position and @param num_bytes
	 * for the passed pointers to now point to.
	 */
	void parse_pos_and_num_bytes(char *input, unsigned int *position, unsigned int *num_bytes){
		int i = 0, j = 0;
		char *pos = malloc(11); // Maximum digits in a 16 bit int is 10
		char *num = malloc(11);
		while(input[i++] != SPACE);
		while(input[i++] != SPACE);
		while(input[i] != SPACE) pos[j++] = input[i++];
		pos[j] = 0; j = 0; i++;
		while(input[i] != NEWLINE) num[j++] = input[i++];
		num[j] = 0;
		*position = atoi(pos);
		*num_bytes = atoi(num);
		free(pos); free(num);
	}

	/** 
	 * Given @param attr, creates a string with the name of each activated attribute bit.
	 * The caller must free() the return value.
	*/
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

	/** 
	 * Given a cluster number, returns the disk offset where that cluster begins.
	*/
	off_t get_cluster_offset(int clust_num){
		fatinfo_t *fi = &fat_info;
		return (clust_num == 0x0) ? root_dir.offset: ((clust_num - fi->BPB_RootClus)* fi->BPB_SecPerClus + fi->FirstDataSector) * fi->BPB_BytsPerSec;
	}

	/**
	 * Scans the FAT table for any unallocated clusters and returns the first one encountered.
	*/
	unsigned int find_unallocated_clust(){
		fatinfo_t *fi = &fat_info;
		unsigned int i = 0;
		while(fi->FAT_table[i] != 0) i++;
		return i;
	}

	/** 
	 * Assumes entry to be made is a directory because the only entry that this program can make is a directory
	*/
	unsigned char * make_entry(char *name, unsigned int clust){
		unsigned char *entry = malloc(32);
		unsigned short hi = (clust & HI_MASK) >> 16;
		unsigned short lo = clust & LO_MASK;
		int i = 0;
		while(name[i] != 0){
			entry[i] = name[i];
			i++;

		}
		while(i < 11){
			entry[i] = SPACE;
			i++;
		}
		entry[i] = ATTR_DIRECTORY;
		writeLittleEnd((entry+20), hi, 2);
		writeLittleEnd((entry+26), lo, 2);
		i = 28;
		while(i < 32){
			entry[i++] = 0;
		}
		return entry;
	}

	/** 
	 * Updates the FAT table on disk at @param clust with value @param next_clust
	 * Also manually updates the same value in the FAT table already in memory to prevent another disk access.
	*/
	void update_fat(unsigned int clust, unsigned int next_clust){
		off_t fat_offset = fat_info.fat_offset + 4 * clust;
		unsigned char buff[4];
		writeLittleEnd(buff, next_clust, 4);
		fseek(fat_info.img_fp, fat_offset, SEEK_SET);
		if(fwrite(buff, 1, 4, fat_info.img_fp) != 4){
			fprintf(stderr, "Error updating FAT\n");
		}
		fat_info.FAT_table[clust] = next_clust;
	}
/********************************************************************************************/
/* STARTUP FUNCTIONS */
/********************************************************************************************/

	/** 
	 * On startup, parses the boot sector to fill global structs fat_info, pwd, and root_dir.
	*/
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
		wd->first_clust_num = root->first_clust_num = fi->BPB_RootClus;
		wd->cluster = read_cluster(fi->FirstDataSector * fi->BPB_BytsPerSec);
		root->cluster = read_cluster(fi->FirstDataSector * fi->BPB_BytsPerSec);
		free(boot_sector);
	}

	/** 
	 * Opens file with read and write privileges and passes the file pointer and file descriptor to the fat_info struct.
	*/
	void open_img(char *filename){
		fatinfo_t *fi = &fat_info;
		FILE *fp;
		int fd;
		fp = fopen(filename, "r+b"); //TODO set to write privileges
		if(fp == NULL){
			fprintf(stderr, "img file not opened\n");
			exit(EXIT_FAILURE);
		}
		fd = fileno(fp);
		fi->img_fp = fp;
		fi->img_fd = fd;
	}

	/** 
	 * Reads the FAT table into memory
	*/
	void read_fat(){
		fatinfo_t *fi = &fat_info;
		unsigned int size = fi->BPB_FATSz32 * fi->BPB_BytsPerSec * fi->BPB_SecPerClus;
		int length = size / sizeof(unsigned int), UIntsPerClus = (fi->BPB_BytsPerSec * fi->BPB_SecPerClus) / sizeof(unsigned int);
		// dummy value here to silence the compiler. read_cluster() will do malloc for us.
		unsigned char * cluster = 0;
		int i, j = 0;
		fi->FAT_table = (unsigned int *) malloc(size);
		/* 
		This is ugly, I know. I only want to have 1 cluster in memory at a time so this monstrosity (beauty because it works) is the result.
		If i = 0 or some multiple of UnsignedIntsPerSec, read in the next cluster. j tracks which cluster to read.
		*/
		for(i = 0; i < length; i++){
			if(i % UIntsPerClus == 0){
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
				display_info();
			}

			else if(strncmp(cmd_line,"stat",4)==0){
				do_ls_cd_stat_size_read_rmdir_mkdir(cmd_line, STAT);
			}
			
			else if(strncmp(cmd_line,"size",4)==0) {
				do_ls_cd_stat_size_read_rmdir_mkdir(cmd_line, SIZE);
			}

			else if(strncmp(cmd_line,"volume",6)==0){
				display_volume();
			}

			else if(strncmp(cmd_line,"cd",2)==0) {
				do_ls_cd_stat_size_read_rmdir_mkdir(cmd_line, CD);
			}

			else if(strncmp(cmd_line,"ls",2)==0) {
				do_ls_cd_stat_size_read_rmdir_mkdir(0, LS);
			}

			else if(strncmp(cmd_line,"read",4)==0) {
				do_ls_cd_stat_size_read_rmdir_mkdir(cmd_line, READ);
			}

			else if(strncmp(cmd_line,"mkdir",5)==0){
				do_ls_cd_stat_size_read_rmdir_mkdir(cmd_line, MKDIR);
			}

			else if(strncmp(cmd_line,"rmdir",5)==0){
				do_ls_cd_stat_size_read_rmdir_mkdir(cmd_line, RMDIR);
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

