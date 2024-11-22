/*
 * Copyright (C) 2024 TheProgxy <theprogxy@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <termcap.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/klog.h>
#include <errno.h>
#include <string.h>

typedef unsigned char bool;

#define FALSE 0
#define TRUE 1
#define CHR_TO_INT(chr) ((int)chr - 48)
#define IS_A_VAL(chr) (chr >= 48 && chr <= 57)
#define MAX(a, b) a > b ? a : b
#define MIN(a, b) a < b ? a : b

// Define log levels as an enum
typedef enum LogLevels {
    LOG_EMERG,     // Emergency
    LOG_ALERT,     // Alert
    LOG_CRIT,      // Critical
    LOG_ERR,       // Error
    LOG_WARNING,   // Warning
    LOG_NOTICE,    // Notice
    LOG_INFO,      // Info
    LOG_DEBUG      // Debug
} LogLevels;

// Define color codes for each log level
#define RESET_COLOR       "\033[0m"           // Reset to default color
#define EMERGENCY_COLOR   "\033[38;5;196m"    // Bright red for immediate emergencies
#define ALERT_COLOR       "\033[38;5;208m"    // Bold orange for high alert
#define CRITICAL_COLOR    "\033[38;5;160m"    // Deep red for critical issues
#define ERROR_COLOR       "\033[38;5;197m"    // Brighter red for standard errors
#define WARNING_COLOR     "\033[38;5;214m"    // Yellow-orange for warnings
#define NOTICE_COLOR      "\033[38;5;33m"     // Blue for notices
#define INFO_COLOR        "\033[38;5;37m"     // Green for informational messages
#define DEBUG_COLOR       "\033[38;5;243m"    // Grey for debug messages
#define TIMESTAMP_COLOR   "\033[38;5;39m"     // Cyan for timestamps
#define KMESG_COLOR       "\033[38;5;208m"    // Orange

const char* log_level_colors[] = {
    EMERGENCY_COLOR,  // LOG_EMERG
    ALERT_COLOR,      // LOG_ALERT
    CRITICAL_COLOR,   // LOG_CRIT
    ERROR_COLOR,      // LOG_ERR
    WARNING_COLOR,    // LOG_WARNING
    NOTICE_COLOR,     // LOG_NOTICE
    INFO_COLOR,       // LOG_INFO
    DEBUG_COLOR       // LOG_DEBUG
};

#define KMESG_ERR(fmt, ...) printf(ERROR_COLOR "KMESG_ERROR" RESET_COLOR "(line: %u):" fmt, __LINE__, ##__VA_ARGS__)
#define kmesg_perror(fmt, ...) KMESG_ERR(fmt WARNING_COLOR "%s.\n" RESET_COLOR, ##__VA_ARGS__, strerror(errno))

#define KMESG_VERSION "1.1.0"

// Kernel function types
#define READ          2
#define READ_ALL      3
#define READ_CLEAR    4
#define CLEAR         5
#define CONSOLE_OFF   6
#define CONSOLE_ON    7
#define CONSOLE_LEVEL 8
#define SIZE_UNREAD   9
#define SIZE_BUFFER   10

// KMESG function type
#define COLOR_DEMO           11
#define READ_UNREAD          12
#define HELPER               13
#define SET_MIN_SEVERITY     14
#define SET_MIN_FACILITY     15
#define LIST_LEVELS          16
#define INVALID_FLAG         17
#define DEFAULT_MSG_BUF_SIZE 8192

const char* mod_func_names[] = {"", "", "READ", "READ_ALL" , "READ_CLEAR", "CLEAR", "CONSOLE_OFF", "CONSOLE_ON", "CONSOLE_LEVEL", "SIZE_UNREAD", "SIZE_UNREAD", "SIZE_BUFFER"};

// Kern log levels (severity levels)
#define KERN_EMERG   0   
#define KERN_ALERT   1  
#define KERN_CRIT    2  
#define KERN_ERR     3  
#define KERN_WARNING 4  
#define KERN_NOTICE  5  
#define KERN_INFO    6
#define KERN_DEBUG   7 

const char* severities_names[] = {"KERN_EMERG", "KERN_ALERT", "KERN_CRIT", "KERN_ERR", "KERN_WARNING", "KERN_NOTICE", "KERN_INFO", "KERN_DEBUG"};

// Facility levels
typedef enum FacilityLevels{ FACILITY_KERNEL, FACILITY_USER, FACILITY_MAIL, FACILITY_DAEMON, FACILITY_AUTH, FACILITY_SYSLOG, FACILITY_LPR, FACILITY_NEWS, FACILITY_UUCP, FACILITY_CRON, FACILITY_AUTHPRIV, FACILITY_FTP, FACILITY_NTP, FACILITY_SECURITY, FACILITY_CONSOLE, FACILITY_SOLARIS_CRON, FACILITY_LOCAL0, FACILITY_LOCAL1, FACILITY_LOCAL2, FACILITY_LOCAL3, FACILITY_LOCAL4, FACILITY_LOCAL5, FACILITY_LOCAL6, FACILITY_LOCAL7} FacilityLevels;

const char* facilities_names[] = { "FACILITY_KERNEL", "FACILITY_USER", "FACILITY_MAIL", "FACILITY_DAEMON", "FACILITY_AUTH", "FACILITY_SYSLOG", "FACILITY_LPR", "FACILITY_NEWS", "FACILITY_UUCP", "FACILITY_CRON", "FACILITY_AUTHPRIV", "FACILITY_FTP", "FACILITY_NTP", "FACILITY_SECURITY", "FACILITY_CONSOLE", "FACILITY_SOLARIS-cron", "FACILITY_LOCAL0", "FACILITY_LOCAL1", "FACILITY_LOCAL2", "FACILITY_LOCAL3", "FACILITY_LOCAL4", "FACILITY_LOCAL5", "FACILITY_LOCAL6", "FACILITY_LOCAL7"};

// Static Variables
static unsigned int min_severity = KERN_INFO;
static unsigned int min_facility = FACILITY_KERNEL;
static unsigned char mod_func = 0;
static int kern_msg_buf_size = 0;
static int log_level = KERN_INFO;
static bool less_mode = FALSE;
static bool reverse_mode = FALSE;

unsigned int str_len(char* str) {
	if (str == NULL) return 0;
	unsigned int i = 0;
	while (str[i] != '\0') ++i;
	return i;
}

static void mem_cpy(void* dest, void* src, size_t size) {
	if (dest == NULL || src == NULL) return;
	for (size_t i = 0; i < size; ++i) ((unsigned char*) dest)[i] = ((unsigned char*)src)[i];
	return;
}

static void mem_set(void* dest, unsigned char val, size_t size) {
	if (dest == NULL) return;
	for (size_t i = 0; i < size; ++i) ((unsigned char*) dest)[i] = val;
	return;
}

unsigned int ref_chr_cnt(char* str, unsigned int len, char chr) {
	unsigned int ref_cnt = 0;
	if (str == NULL) return 0;
	for (unsigned int i = 0; i < len; ++i) if (str[i] == chr) ref_cnt++;
	return ref_cnt;
}

long long int find_chr(char* str, unsigned int len, char chr) {
	if (str == NULL) return -2;
	for (unsigned int i = 0; i < len; ++i) if (str[i] == chr) return (int) i;
	return -1;
}

long long int str_to_int(char* str) {
	long long int value = 0;
	if (str == NULL) return 0;
	unsigned int i = 0;
	while (str[i] != '\0') {
		if (!IS_A_VAL(str[i])) {
			KMESG_ERR(" this is not a valid value: " CRITICAL_COLOR "'%s'" RESET_COLOR ".\n", str);
			return -1;
		}
		value *= 10;
		value += CHR_TO_INT(str[i]);
		++i;
	}
	return value;
}

char** extract_lines(char* str, unsigned int len, unsigned int* lines_cnt) {
	unsigned int ref_cnt = ref_chr_cnt(str, len, '\n');
	char** lines = (char**) calloc(ref_cnt, sizeof(char*));
	if (lines == NULL) {
		KMESG_ERR("failed to allocate lines buff.\n");
		return NULL;
	}

	unsigned int str_pos = 0;
	for (*lines_cnt = 0; *lines_cnt < ref_cnt; ++(*lines_cnt)) {
		long long int ref_pos = find_chr(str + str_pos, len - str_pos, '\n');
		if (ref_pos < 0) KMESG_ERR("ref not found, str_pos: %u, line_cnt: %u.\n", str_pos, *lines_cnt + 1);
		lines[*lines_cnt] = (char*) calloc(ref_pos + 1, sizeof(char));
		if (lines[*lines_cnt] == NULL) {
			for (unsigned int i = 0; i < *lines_cnt; ++i) free(lines[i]);
			free(lines);
			KMESG_ERR("failed to allocate %u line.\n", *lines_cnt + 1);
			return NULL;
		}
		mem_cpy(lines[*lines_cnt], str + str_pos, ref_pos);
		lines[*lines_cnt][ref_pos] = '\0';
		str_pos += ref_pos + 1;
	}

	return lines;
}

void filter_severity_facility(char*** lines, unsigned int* lines_cnt) {
	char log_level_str[25] = {0};

	for (unsigned int i = 0; i < *lines_cnt; ++i) {
		// Line example "<log_level_num> [timestamp] info..."
		char* str_line = (*lines)[i];
		unsigned int len = str_len(str_line);
		unsigned int str_pos = 1;

		// Extract the log level is composed by severity and facility (combined value = (facility x 8) + severity), in this way we can filter messages by facility and severity
		long long int log_level_end_pos = find_chr(str_line + str_pos, len - str_pos, '>');
		if (log_level_end_pos < 0) {
			free((*lines)[i]);
			for (unsigned int t = i; t < *lines_cnt - 1; ++t) (*lines)[t] = (*lines)[t + 1];
			(*lines_cnt)--;
			--i;
			continue;
		}
		
		mem_cpy(log_level_str, str_line + str_pos, log_level_end_pos);
		log_level_str[log_level_end_pos] = '\0';

		unsigned int log_level = str_to_int(log_level_str);
		unsigned int facility = log_level / 8;
		unsigned int severity = log_level % 8;
		mem_set(log_level_str, 0, 25); // Reset the string after use

		if (severity > min_severity || facility > min_facility) {
			free((*lines)[i]);
			for (unsigned int t = i; t < *lines_cnt - 1; ++t) (*lines)[t] = (*lines)[t + 1];
			(*lines_cnt)--;
			--i;
		}
	}

	*lines = (char**) realloc(*lines, sizeof(char*) * (*lines_cnt));

	return;
}

bool print_line(char* str_line) {
	// Line example "<log_level_num> [timestamp] info..."
	unsigned int len = str_len(str_line);
	unsigned int str_pos = 1;

	// Extract the log level is composed by severity and facility (combined value = (facility x 8) + severity), in this way we can filter messages by facility and severity
	long long int log_level_end_pos = find_chr(str_line + str_pos, len - str_pos, '>');
	if (log_level_end_pos < 0) {
		KMESG_ERR("invalid string format: '%s'.\n", str_line);
		return FALSE;
	}

	char* log_level_str = (char*) calloc(log_level_end_pos + 1, sizeof(char));
	if (log_level_str == NULL) {
	   KMESG_ERR("failed to allocate the log level buf.\n");
	   return FALSE;
	}

	mem_cpy(log_level_str, str_line + str_pos, log_level_end_pos);
	log_level_str[log_level_end_pos] = '\0';
	str_pos += log_level_end_pos + 1;

	unsigned int log_level = str_to_int(log_level_str);
	unsigned int severity = log_level % 8;
	free(log_level_str);

	// Extract the timestamp
	long long int timestamp_end_pos = find_chr(str_line + str_pos, len - str_pos, ']');
	if (timestamp_end_pos < 0) {
		KMESG_ERR("invalid string format: '%s'.\n", str_line);
		return FALSE;
	} 

	char* timestamp = (char*) calloc(timestamp_end_pos + 2, sizeof(char));
	if (timestamp == NULL) {
		KMESG_ERR("failed to allocate the timestamp buff.\n");
		return FALSE;
	}
	mem_cpy(timestamp, str_line + str_pos, timestamp_end_pos + 1);
	timestamp[timestamp_end_pos + 1] = '\0';
	str_pos += timestamp_end_pos + 1;

	// Extract the module defined identifier, we check for the pos of the column (like "MODULE-NAME_LOG-LEVEL: ...")
	long long int column_ref = find_chr(str_line + str_pos, len - str_pos, ':');
	// Print the rest if the identifier is not present
	if (column_ref < 0) {
		printf(TIMESTAMP_COLOR "%s" RESET_COLOR "%s\n", timestamp, (str_line + str_pos));
		free(timestamp);
		return TRUE;
	}
	
	char* module_identifier = (char*) calloc(column_ref + 2, sizeof(char)); 
	if (module_identifier == NULL) {
		free(timestamp);
		KMESG_ERR("failed to allocate module_identifier.\n");
		return FALSE;
	}

	mem_cpy(module_identifier, str_line + str_pos, column_ref + 1);
	module_identifier[column_ref + 1] = '\0';
	str_pos += column_ref + 1;

	printf(TIMESTAMP_COLOR "%s" RESET_COLOR "%s%s" RESET_COLOR "%s\n", timestamp, log_level_colors[severity], module_identifier, (str_line + str_pos));

	free(timestamp);
	free(module_identifier);

	return TRUE;
}

struct termios enable_raw_mode() {
	struct termios orig_termios = {0};
    struct termios raw = {0};

    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &orig_termios);
    raw = orig_termios;

    // Modify settings for raw mode
	raw.c_lflag &= ~(ECHO | ICANON); // Disable echo and canonical mode
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) {
		kmesg_perror("failed to set tcsetattr");
		return orig_termios;
	}
	return orig_termios;
}

void disable_raw_mode(struct termios orig_termios) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios); // Restore original settings
	return;
}

bool print_screen(char* clear_cmd, long long int start_line, unsigned int term_height, char** lines, long long int lines_cnt, struct termios original_settings) {
	printf("%s", clear_cmd); 
	
	for (long long int i = start_line, j = 0; (j < term_height) && (i < lines_cnt); ++i, ++j) {
		if (i < 0) {
			printf("\n");
			continue;
		}

		if (!print_line(lines[i])) {
			disable_raw_mode(original_settings);
			return FALSE;
		}
	}

	printf(KMESG_COLOR "KMESG: " RESET_COLOR "Line %lld out of %lld (%u%%)\n:", start_line + term_height, lines_cnt, (unsigned int) (((float)(start_line + term_height) / lines_cnt) * 100.0f));
	fflush(stdout);

	return TRUE;
}

void print_less(char** lines, long long int lines_cnt) {
	// Load termcap and enable raw mode
    char term_buffer[2048] = {0};
    if (tgetent(term_buffer, getenv("TERM")) <= 0) return;

    char* clear_cmd = tgetstr("cl", NULL);
    long long int term_height = tgetnum("li") - 2;
    struct termios original_settings = enable_raw_mode();

	// Init Screen
	long long int start_line = -term_height + 1; 
	if (!print_screen(clear_cmd, start_line, term_height, lines, lines_cnt, original_settings)) return;
	
	char c = 0;
	char buf[12];
	unsigned char buf_index = 0;
	while (read(STDIN_FILENO, &c, 1) == 1) {
		if (c == 'q') break;
		else if (c == 'g' || c == '<') start_line = -term_height + 1;
		else if (c == 'G' || c == '>') start_line = lines_cnt - term_height;
		else if ((c == 'j') && (start_line < lines_cnt - term_height)) start_line++; 
		else if ((c == 'k') && (start_line > -term_height + 1)) start_line--;
		else if ((c == ' ') && (start_line < lines_cnt - term_height)) {
			start_line += term_height; 
			start_line = MIN(start_line, lines_cnt - term_height);
		} else if ((c == 'b') && (start_line > -term_height + 1)) {
			start_line -= term_height;
			start_line = MAX(start_line, -term_height + 1);
		}
		else if (c == '\033') {
			char seq[3];
			if (read(STDIN_FILENO, &seq[0], 1) == 0) break;
			if (read(STDIN_FILENO, &seq[1], 1) == 0) break;
			
			if (seq[0] == '[') {
				if ((seq[1] == 'A') && (start_line > -term_height + 1)) start_line--;
				else if ((seq[1] == 'B') && (start_line < lines_cnt - term_height)) start_line++;
			}
		} else if (IS_A_VAL(c)) {
			buf[buf_index] = c;
			buf_index++;

			while(read(STDIN_FILENO, &c, 1) == 1) {
				if (IS_A_VAL(c)) {
					// Shift the chars inside the buffer left
					if (buf_index == 11) mem_cpy(buf, buf + 1, 11);
					buf[buf_index] = c;
					buf_index = (buf_index + 1) % 12;
					continue;
				} else if (c == '\n') break;
			}

			if (buf_index) {
				long long int line = str_to_int(buf);
				if (line <= 0 || (line > lines_cnt)) {
					if (!print_screen(clear_cmd, start_line, term_height - 1, lines, lines_cnt, original_settings)) return;
					if (line < 0) KMESG_ERR(" Not a value: '%s'\n", buf);
					else if (line > lines_cnt || line == 0) KMESG_ERR(" Invalid value: %lld, it must be between 1 and %lld\n", line, lines_cnt);
					buf_index = 0;
					mem_set(buf, 0, 12);
					continue;
				}

				start_line = line - term_height;
				if (!print_screen(clear_cmd, start_line, term_height, lines, lines_cnt, original_settings)) return;
			} 

			buf_index = 0;
			mem_set(buf, 0, 12);
		}
		
		if (!print_screen(clear_cmd, start_line, term_height, lines, lines_cnt, original_settings)) return;
	}

    disable_raw_mode(original_settings);
    
	return;

}

void reverse_str_arr(char*** str_arr, unsigned int size) {
	for (unsigned int i = 0; i < (size >> 1); ++i) {
		char* temp = (*str_arr)[i];
		(*str_arr)[i] = (*str_arr)[size - 1 - i];
		(*str_arr)[size - 1 - i] = temp;
	}
	return;
}

void print_kmsg(char* kmesg, unsigned int len) {
	printf(KMESG_COLOR "KMESG: " RESET_COLOR "Read %d bytes, messages in the kernel ring buffer: \n", len);
	// Extract the lines and then process each one of them
	unsigned int lines_cnt = 0;
	char** lines = extract_lines(kmesg, len, &lines_cnt);
	if (lines == NULL || !lines_cnt) return; 
	filter_severity_facility(&lines, &lines_cnt);
	if (reverse_mode) reverse_str_arr(&lines, lines_cnt);

	if (less_mode) print_less(lines, lines_cnt);
	else {
		for (unsigned int i = 0; i < lines_cnt; ++i) print_line(lines[i]);
	}
		
	for (unsigned int i = 0; i < lines_cnt; ++i) free(lines[i]);
	free(lines);
	
	return;
}

void print_color_demo(void) {
	printf(KMESG_COLOR "KMESG:" RESET_COLOR "color demo:\n");
	printf(EMERGENCY_COLOR "  -- EMERGENCY_COLOR --  " RESET_COLOR "\n");
	printf(ALERT_COLOR "  -- ALERT_COLOR --  " RESET_COLOR "\n");
	printf(CRITICAL_COLOR "  -- CRITICAL_COLOR --  " RESET_COLOR "\n");
	printf(ERROR_COLOR "  -- ERROR_COLOR -- " RESET_COLOR "\n");
	printf(WARNING_COLOR "  -- WARNING_COLOR --  " RESET_COLOR "\n");
	printf(NOTICE_COLOR "  -- NOTICE_COLOR --  " RESET_COLOR "\n");
	printf(INFO_COLOR "  -- INFO_COLOR --  " RESET_COLOR "\n");
	printf(DEBUG_COLOR "  -- DEBUG_COLOR --  " RESET_COLOR "\n");
	printf(TIMESTAMP_COLOR "  -- TIMESTAMP_COLOR --  " RESET_COLOR "\n");
	return;
}

void print_list_levels(void) {
	unsigned int severities_names_len = sizeof(severities_names)/sizeof(severities_names[0]);
	unsigned int facilities_names_len = sizeof(facilities_names)/sizeof(facilities_names[0]);
	printf("Severity Levels:\n");
	for (unsigned int i = 0; i < severities_names_len; ++i) printf(" - %s%c\n", severities_names[i], i + 1 == sizeof(severities_names_len) ? '.' : ';');
	printf("\n");
	printf("Facility Levels:\n");
	for (unsigned int i = 0; i < facilities_names_len; ++i) printf(" - %s%c\n", facilities_names[i], i + 1 == sizeof(facilities_names_len) ? '.' : ';');
	printf("\n");
	return;
}

void print_helper(void) {
	printf("Usage: kmesg [-flag[=val]].\n");
	printf("Those are the flags available:\n");
	printf("\t-C:  Clear the kernel ring buffer\n");
	printf("\t-R:  Await until the kernel log buffer is nonempty, and then read at most 'len' bytes, where 'len' is the value passed after the flag, otherwise the default value '%u'.\n", DEFAULT_MSG_BUF_SIZE);
	printf("\t-u:  Return the number of bytes currently available to be read from the kernel log buffer.\n");
	printf("\t-d:  Print the color demo, to show the color palette used for each log level.\n");
	printf("\t-ra: This is the default behaviour used by KMESG. Read all messages remaining in the ring buffer. If a value is passed after the flag, reads the last 'val' bytes from the log buffer.\n");
	printf("\t-rc: Read and clear all messages remaining in the ring buffer. If a value is passed after the flag, reads the last 'val' bytes from the log buffer.\n");
	printf("\t-ru: Read the messages that have not been read. It is similar to executing -r with -u returned bytes len.\n");
	printf("\t-rv: Print in reverse.\n");
	printf("\t-ce: Set the console log level to the default, so that messages are printed to the console.\n");
	printf("\t-cd: Set the console log level to the minimum, so that no messages are printed to the console.\n");
	printf("\t-cl: Print using a 'less' mode, the following commands apply only to the less mode:\n");
	printf("\t\tq: Exit.\n");
	printf("\t\tg: Go to the beginning, alternatively can be used '<'.\n");
	printf("\t\tG: Go to the end, alternatively can be used '>'.\n");
	printf("\t\tj: Scroll down one line, alternatively can be used the 'arrow down'.\n");
	printf("\t\tk: Scroll up one line, alternatively can be used the 'arrow up'.\n");
	printf("\t\tSpace: Scroll down one screen.\n");
	printf("\t\tb: Scroll up one screen.\n");
	printf("\t\t[numbers]-Enter: Navigate to the specified line (max 12 digits). Exceeding 12 shifts input left to make space for the new digit.\n");
	printf("\t-L:  Set the console log level to the value passed after the flag, which must be an integer between 1 and 8 (inclusive).\n");
	printf("\t-s:  Set the MIN_SEVERITY using the value passed after the flag. The default value is '%s'.\n", severities_names[min_severity]);
	printf("\t-f:  Set the MIN_FACILITY using the value passed after the flag. The default value is '%s'.\n", facilities_names[min_facility]);
	printf("\t-l:  List SEVERITY levels and FACILITY levels.\n");
	printf("\t-h:  Show this page.\n");
	printf("\n" KMESG_COLOR "KMESG: " DEBUG_COLOR "A colored alternative to " NOTICE_COLOR "dmesg" WARNING_COLOR ", by" KMESG_COLOR " \'TheProgxy\'" RESET_COLOR ", (" KMESG_COLOR "KMESG_VERSION: " TIMESTAMP_COLOR KMESG_VERSION RESET_COLOR").\n");
	return; 
}

void read_flag(char* flag_arg) {
	unsigned int arg_len = str_len(flag_arg);
	unsigned int internal_func = 0;
	if (!mod_func) {
		if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'C') mod_func = CLEAR; 
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'R') mod_func = READ;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'u') mod_func = SIZE_UNREAD; 
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'd') mod_func = COLOR_DEMO;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'a') mod_func = READ_ALL;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'c') mod_func = READ_CLEAR;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'u') mod_func = READ_UNREAD;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'v') { 
			reverse_mode = TRUE;
			return;
		} else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'c' && flag_arg[2] == 'e') mod_func = CONSOLE_ON;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'c' && flag_arg[2] == 'd') mod_func = CONSOLE_OFF;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'c' && flag_arg[2] == 'l') { 
			less_mode = TRUE;
		} else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'L') mod_func = CONSOLE_LEVEL;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'l') mod_func = LIST_LEVELS;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 's') internal_func = SET_MIN_SEVERITY;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'f') internal_func = SET_MIN_FACILITY;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'h') mod_func = HELPER;
		else {
			mod_func = INVALID_FLAG;
			KMESG_ERR("invalid flag: '%s'\n.", flag_arg);
			return;
		}
	} else {
		if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 's') internal_func = SET_MIN_SEVERITY;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'f') internal_func = SET_MIN_FACILITY;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'h') mod_func = HELPER;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'v') reverse_mode = TRUE;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'c' && flag_arg[2] == 'l') less_mode = TRUE;
		else {
			mod_func = INVALID_FLAG;
			KMESG_ERR("invalid flag: '%s'\n.", flag_arg);
			return;
		}
	}
	
	if (mod_func == HELPER || mod_func == LIST_LEVELS || mod_func == COLOR_DEMO) return;

	if (internal_func) {
		long long int value_pos = find_chr(flag_arg, arg_len, '=');
		if (value_pos < 0) return;
		int value = str_to_int(flag_arg + value_pos + 1);
		if (value < 0) {
			mod_func = INVALID_FLAG;
			return;
		}
		if (internal_func == SET_MIN_SEVERITY) min_severity = value;
		else min_facility = value;
		return;
	}

	if (mod_func == READ || mod_func == READ_ALL || mod_func == READ_CLEAR) {
		long long int value_pos = find_chr(flag_arg, arg_len, '=');
		if (value_pos < 0) return;
		kern_msg_buf_size = str_to_int(flag_arg + value_pos + 1);
		if (kern_msg_buf_size < 0) {
			mod_func = INVALID_FLAG;
			return;
		}
	} else if (mod_func == CONSOLE_LEVEL) {
		long long int value_pos = find_chr(flag_arg, arg_len, '=');
		if (value_pos < 0) return;
		log_level = str_to_int(flag_arg + value_pos + 1);
		if (log_level < 0) {
			mod_func = INVALID_FLAG;
			return;
		} else if (log_level > 8 || log_level < 1) {
			mod_func = INVALID_FLAG;
			KMESG_ERR("invalid log level: %d, log levels must be in interval [1..8].\n", log_level);
			return;
		}
	} 
	
	return;
}

int main(int argc, char* argv[]) {
	if (argc > 1) {
		unsigned int arg_cnt = 0;
		argc--;
		while (arg_cnt++, argc--) {
			read_flag(argv[arg_cnt]);
			if (mod_func == INVALID_FLAG) return -1;
		}
	}

	if (mod_func == HELPER) {
		print_helper();
		return 0;
	} else if (mod_func == COLOR_DEMO) {
		print_color_demo();
		return 0;
	} else if (mod_func == LIST_LEVELS) {
		print_list_levels();
		return 0;
	}

	if (!mod_func) mod_func = READ_ALL;

	if (mod_func == READ || mod_func == READ_ALL || mod_func == READ_CLEAR || mod_func == READ_UNREAD) {
		if (!kern_msg_buf_size && (mod_func == READ_ALL || mod_func == READ_CLEAR)) {
			if ((kern_msg_buf_size = klogctl(SIZE_BUFFER, NULL, 0)) < 0) {
				kmesg_perror("failed to execute the function: " CRITICAL_COLOR "SIZE_BUFFER" RESET_COLOR ", because: ");
				return -1;
			}
		} else if (mod_func == READ_UNREAD) { 
			if ((kern_msg_buf_size = klogctl(SIZE_UNREAD, NULL, 0)) < 0) {
				kmesg_perror("failed to execute the function: " CRITICAL_COLOR "SIZE_UNREAD" RESET_COLOR ", because: ");
				return -1;
			}
			mod_func = READ; // Change the mod func to READ, to execute the READ command, as part of the READ_UNREAD command
		} else if (!kern_msg_buf_size) kern_msg_buf_size = DEFAULT_MSG_BUF_SIZE;
		
		if (less_mode) printf("\033[?1049h"); // Switch to the alternate screen buffer
		printf(KMESG_COLOR "KMESG:" RESET_COLOR " the buffer size is set to \'%d\' bytes.\n", kern_msg_buf_size);	

		char* msg_buff = (char*) calloc(kern_msg_buf_size, sizeof(char));
		if (msg_buff == NULL) {
			KMESG_ERR("failed to allocate the msg buffer.\n");
			return -1;
		}

		int ret = 0;
		if ((ret = klogctl(mod_func, msg_buff, kern_msg_buf_size)) < 0) {
			free(msg_buff);
			kmesg_perror("failed to execute the function: " CRITICAL_COLOR "%s" RESET_COLOR ", because: ", mod_func_names[mod_func]);
			return -1;
		}

		print_kmsg(msg_buff, ret);
		free(msg_buff);
		if (less_mode) printf("\033[?1049l"); // Restore the primary screen buffer

	} else if (mod_func == CLEAR || mod_func == CONSOLE_ON || mod_func == CONSOLE_OFF || mod_func == SIZE_UNREAD || mod_func == CONSOLE_LEVEL) {
		int ret = 0;
		if (mod_func == CONSOLE_LEVEL) ret = klogctl(mod_func, NULL, log_level);
		else ret = klogctl(mod_func, NULL, 0);
		
		if (ret < 0) {
			kmesg_perror("failed to execute the function: " CRITICAL_COLOR "%s" RESET_COLOR ", because: ", mod_func_names[mod_func]);
			return -1;
		}

		if (mod_func == SIZE_UNREAD) printf("The number of bytes currently available to be read from the kernel log buffer is: %d.\n", ret);	
		else printf("Operation: " CRITICAL_COLOR "%s" RESET_COLOR "executed successfully.\n", mod_func_names[mod_func]);	

	} else if (mod_func == COLOR_DEMO) print_color_demo();

	return 0;
}
