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
#include "./utils.h"

/* -------------------------------------------------------------------------------------------------------- */
// ------------------ 
//  Static Variables
// ------------------ 
static KMESGlobal kmesglobal = {
	.min_severity = KERN_INFO,
	.min_facility = FACILITY_KERNEL,
	.log_level = KERN_INFO,
};

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
char** extract_lines(const char* str, unsigned int len, unsigned int* lines_cnt);

/* -------------------------------------------------------------------------------------------------------- */
// -----------------------
//  Functions Definitions
// -----------------------
char** extract_lines(const char* str, unsigned int len, unsigned int* lines_cnt) {
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
			for (unsigned int i = 0; i < *lines_cnt; ++i) SAFE_FREE(lines[i]);
			SAFE_FREE(lines);
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
			SAFE_FREE((*lines)[i]);
			for (unsigned int t = i; t < *lines_cnt - 1; ++t) (*lines)[t] = (*lines)[t + 1];
			(*lines_cnt)--;
			--i;
			continue;
		}
		
		mem_cpy(log_level_str, str_line + str_pos, log_level_end_pos);
		log_level_str[log_level_end_pos] = '\0';

		unsigned int log_level = str_to_int(log_level_str);
		int facility = log_level / 8;
		int severity = log_level % 8;
		mem_set(log_level_str, 0, 25); // Reset the string after use

		if (severity > kmesglobal.min_severity || facility > kmesglobal.min_facility) {
			SAFE_FREE((*lines)[i]);
			for (unsigned int t = i; t < *lines_cnt - 1; ++t) (*lines)[t] = (*lines)[t + 1];
			(*lines_cnt)--;
			--i;
		}
	}

	*lines = (char**) realloc(*lines, sizeof(char*) * (*lines_cnt));

	return;
}

int get_log_level_and_severity(char* str_line, unsigned int len, unsigned int* str_pos, unsigned int* log_level, unsigned int* severity) {
	// Extract the log level is composed by severity and facility (combined value = (facility x 8) + severity), in this way we can filter messages by facility and severity
	long long int log_level_end_pos = find_chr(str_line + *str_pos, len - *str_pos, '>');
	if (log_level_end_pos < 0) {
		KMESG_ERR("invalid string format: '%s'.\n", str_line);
		return FALSE;
	}

	char* log_level_str = (char*) calloc(log_level_end_pos + 1, sizeof(char));
	if (log_level_str == NULL) {
	   KMESG_ERR("failed to allocate the log level buf.\n");
	   return FALSE;
	}

	mem_cpy(log_level_str, str_line + *str_pos, log_level_end_pos);
	log_level_str[log_level_end_pos] = '\0';
	*str_pos += log_level_end_pos + 1;

	*log_level = str_to_int(log_level_str);
	*severity = *log_level % 8;
	SAFE_FREE(log_level_str);
	
	return TRUE;
}

int get_timestamp_and_identifier(char* str_line, unsigned int len, unsigned int* str_pos, char** timestamp, char** module_identifier) {
	// Extract the timestamp
	long long int timestamp_end_pos = find_chr(str_line + *str_pos, len - *str_pos, ']');
	if (timestamp_end_pos < 0) {
		KMESG_ERR("invalid string format: '%s'.\n", str_line);
		return FALSE;
	} 

	*timestamp = (char*) calloc(timestamp_end_pos + 2, sizeof(char));
	if (*timestamp == NULL) {
		KMESG_ERR("failed to allocate the timestamp buff.\n");
		return FALSE;
	}
	
	mem_cpy(*timestamp, str_line + *str_pos, timestamp_end_pos + 1);
	(*timestamp)[timestamp_end_pos + 1] = '\0';
	*str_pos += timestamp_end_pos + 1;

	// Extract the module defined identifier, we check for the pos of the column (like "MODULE-NAME_LOG-LEVEL: ...")
	long long int column_ref = find_chr(str_line + *str_pos, len - *str_pos, ':');
	// Print the rest if the identifier is not present
	if (column_ref < 0) return TRUE;
	
	*module_identifier = (char*) calloc(column_ref + 2, sizeof(char)); 
	if (module_identifier == NULL) {
		SAFE_FREE(*timestamp);
		KMESG_ERR("failed to allocate module_identifier.\n");
		return FALSE;
	}

	mem_cpy(*module_identifier, str_line + *str_pos, column_ref + 1);
	(*module_identifier)[column_ref + 1] = '\0';
	*str_pos += column_ref + 1;
	
	return TRUE;
}

void dump_line(char* str_line, char* timestamp, char* module_identifier, unsigned int str_pos, unsigned int severity) {
	// Check if the timestamp offset matches
	bool matches_offset = str_n_cmp(timestamp + 2, kmesglobal.dump_offset, str_len(kmesglobal.dump_offset)) == 0;
	if (*kmesglobal.dump_offset != '\0' && matches_offset) {
		*kmesglobal.dump_offset = '\0';
	} else if (*kmesglobal.dump_offset != '\0' && !matches_offset) {
		SAFE_FREE(timestamp);
		SAFE_FREE(module_identifier);
		return;
	}
	
	int line_size = 0;
	char line[MAX_DUMP_LINE_SIZE] = {0};
	
	if (kmesglobal.flag_modes & DISABLE_COLORS) {
		if (module_identifier != NULL) line_size = snprintf(line, MAX_DUMP_LINE_SIZE, RESET_COLOR "%s%s%s\n", timestamp, module_identifier, (str_line + str_pos));
		else line_size = snprintf(line, MAX_DUMP_LINE_SIZE, RESET_COLOR "%s" RESET_COLOR "%s\n", timestamp, (str_line + str_pos));
	} else {
		if (module_identifier != NULL) line_size = snprintf(line, MAX_DUMP_LINE_SIZE, TIMESTAMP_COLOR "%s" RESET_COLOR "%s%s" RESET_COLOR "%s\n", timestamp, log_level_colors[severity], module_identifier, (str_line + str_pos));
		else line_size = snprintf(line, MAX_DUMP_LINE_SIZE, TIMESTAMP_COLOR "%s" RESET_COLOR "%s\n", timestamp, (str_line + str_pos));
	}
	
	if (fwrite(line, sizeof(char), line_size, kmesglobal.dump_file) != (size_t) line_size) {
		kmesg_perror("Failed to save the data to the dump file, because: ");
		fclose(kmesglobal.dump_file);
		kmesglobal.dump_file = NULL;
	}

	return;
}

bool print_line(char* str_line) {
	// Line example "<log_level_num> [timestamp] info..."
	unsigned int len = str_len(str_line);
	unsigned int str_pos = 1;
	
	unsigned int log_level = 0;
	unsigned int severity = 0;
	if (!get_log_level_and_severity(str_line, len, &str_pos, &log_level, &severity)) {
		KMESG_ERR("Failed to retrieve log level and severity.\n");
		return FALSE;
	}
	
	char* timestamp = NULL;
	char* module_identifier = NULL;
	if (!get_timestamp_and_identifier(str_line, len, &str_pos, &timestamp, &module_identifier)) {
		KMESG_ERR("Failed to retrieve timestamp and module identifier.\n");
		return FALSE;
	}
	
	if (kmesglobal.flag_modes & DISABLE_COLORS) {
		if (module_identifier != NULL) printf(RESET_COLOR "%s%s%s\n", timestamp, module_identifier, (str_line + str_pos));
		else printf(RESET_COLOR "%s" RESET_COLOR "%s\n", timestamp, (str_line + str_pos));
	} else {
		if (module_identifier != NULL) printf(TIMESTAMP_COLOR "%s" RESET_COLOR "%s%s" RESET_COLOR "%s\n", timestamp, log_level_colors[severity], module_identifier, (str_line + str_pos));
		else printf(TIMESTAMP_COLOR "%s" RESET_COLOR "%s\n", timestamp, (str_line + str_pos));
	}

	if ((kmesglobal.flag_modes & DUMP_KMESG) && kmesglobal.dump_file != NULL) {
		dump_line(str_line, timestamp, module_identifier, str_pos, severity);
	}
	
	SAFE_FREE(timestamp);
	SAFE_FREE(module_identifier);

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
		kmesg_perror("failed to set tcsetattr, because: ");
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

void echo_char(char c) {
	if (c == 127 || c == 8) printf("\b \b");
	else printf("%c", c);
	fflush(stdout);
	return;
}

// TODO: Should most probably either just decompose the following function, or even better give it a dedicated file, with the other termios operations
// TODO: Should most probably add the search function 
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
	char buf[12] = {0};
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
			char seq[3] = {0};
			if (read(STDIN_FILENO, &seq[0], 1) == 0) break;
			if (read(STDIN_FILENO, &seq[1], 1) == 0) break;
			
			if (seq[0] == '[') {
				if ((seq[1] == 'A') && (start_line > -term_height + 1)) start_line--;
				else if ((seq[1] == 'B') && (start_line < lines_cnt - term_height)) start_line++;
			}
		} else if (IS_A_VAL(c)) {
			echo_char(c);
			buf[buf_index] = c;
			buf_index++;
			
			while(read(STDIN_FILENO, &c, 1) == 1) {
				echo_char(c);
			   	if (c == '\n') break;
				if (IS_A_VAL(c)) {
					// Shift the chars inside the buffer left
					if (buf_index == 11) mem_cpy(buf, buf + 1, 11);
					buf[buf_index] = c;
					buf_index = (buf_index + 1) % 12;
				} else if (c == 127 || c == 8) {
					if (buf_index > 0) {
						buf[--buf_index] = '\0';
					}
				}
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

void print_kmsg(char* kmesg, unsigned int len) {
	printf(KMESG_COLOR "KMESG: " RESET_COLOR "Read %d bytes, messages in the kernel ring buffer: \n", len);
	
	// Extract the lines and then process each one of them
	unsigned int lines_cnt = 0;
	char** lines = extract_lines(kmesg, len, &lines_cnt);
	if (lines == NULL || !lines_cnt) return; 
	filter_severity_facility(&lines, &lines_cnt);
	if (kmesglobal.flag_modes & REVERSE_MODE) reverse_str_arr(&lines, lines_cnt);

	if (kmesglobal.flag_modes & DUMP_KMESG) {
		if ((kmesglobal.dump_file = fopen(kmesglobal.dump_file_path, "w")) == NULL) {
			kmesg_perror("Failed to open the dump file, because: ");
		}
	}
	
	if (kmesglobal.flag_modes & LESS_MODE) print_less(lines, lines_cnt);
	else {
		for (unsigned int i = 0; i < lines_cnt; ++i) print_line(lines[i]);
	}
	
	if ((kmesglobal.flag_modes & DUMP_KMESG) && kmesglobal.dump_file != NULL) fclose(kmesglobal.dump_file);

	for (unsigned int i = 0; i < lines_cnt; ++i) SAFE_FREE(lines[i]);
	SAFE_FREE(lines);
	
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
	printf("Usage: kmesg [--flag[=val]].\n");
	printf("Those are the flags available:\n");
	printf("\t--C:  Clear the kernel ring buffer\n");
	printf("\t--R:  Await until the kernel log buffer is nonempty, and then read at most 'len' bytes, where 'len' is the value passed after the flag, otherwise the default value '%u'.\n", DEFAULT_MSG_BUF_SIZE);
	printf("\t--u:  Return the number of bytes currently available to be read from the kernel log buffer.\n");
	printf("\t--d:  Print the color demo, to show the color palette used for each log level.\n");
	printf("\t--ra: This is the default behaviour used by KMESG. Read all messages remaining in the ring buffer. If a value is passed after the flag, reads the last 'val' bytes from the log buffer.\n");
	printf("\t--rc: Read and clear all messages remaining in the ring buffer. If a value is passed after the flag, reads the last 'val' bytes from the log buffer.\n");
	printf("\t--ru: Read the messages that have not been read. It is similar to executing -r with -u returned bytes len.\n");
	printf("\t--rv: Print in reverse.\n");
	printf("\t--ce: Set the console log level to the default, so that messages are printed to the console.\n");
	printf("\t--cd: Set the console log level to the minimum, so that no messages are printed to the console.\n");
	printf("\t--cl: Print using a 'less' mode, the following commands apply only to the less mode:\n");
	printf("\t\tq:     Exit.\n");
	printf("\t\tg:     Go to the beginning, alternatively can be used '<'.\n");
	printf("\t\tG:     Go to the end, alternatively can be used '>'.\n");
	printf("\t\tj:     Scroll down one line, alternatively can be used the 'arrow down'.\n");
	printf("\t\tk:     Scroll up one line, alternatively can be used the 'arrow up'.\n");
	printf("\t\tSpace: Scroll down one screen.\n");
	printf("\t\tb:     Scroll up one screen.\n");
	printf("\t\t[number]-Enter: Navigate to the specified line (max 12 digits). Exceeding 12 shifts input left to make space for the new digit.\n");
	printf("\t--L:  Set the console log level to the value passed after the flag, which must be an integer between 1 and 8 (inclusive).\n");
	printf("\t--s:  Set the MIN_SEVERITY using the value passed after the flag. The default value is '%s'.\n", severities_names[kmesglobal.min_severity]);
	printf("\t--f:  Set the MIN_FACILITY using the value passed after the flag. The default value is '%s'.\n", facilities_names[kmesglobal.min_facility]);
	printf("\t--l:  List SEVERITY levels and FACILITY levels.\n");
	printf("\t--dump: Dump the content of the kernel ring buffer into the specified file, as --dump=file_path.\n");
	printf("\t--dump-offset: Set the timestamp offset from which the content will be dumped, as --dump-offset=0.12.\n");
	printf("\t--no-color: print in old fashioned black & white.\n");
	printf("\t--h:  Show this page.\n");
	printf("\n" KMESG_COLOR "KMESG: " DEBUG_COLOR "A colored alternative to " NOTICE_COLOR "dmesg" WARNING_COLOR ", by" KMESG_COLOR " \'TheProgxy\'" RESET_COLOR ", (" KMESG_COLOR "KMESG_VERSION: " TIMESTAMP_COLOR KMESG_VERSION RESET_COLOR").\n");
	return; 
}

void check_mod_func_flag(char* flag_arg) {
	if (str_n_cmp(flag_arg, "--d", 3) == 0) kmesglobal.mod_func = COLOR_DEMO;
	else if (str_n_cmp(flag_arg, "--l", 3) == 0) kmesglobal.mod_func = LIST_LEVELS;
	else if (str_n_cmp(flag_arg, "--C", 3) == 0) kmesglobal.mod_func = CLEAR; 
	else if (str_n_cmp(flag_arg, "--u", 3) == 0) kmesglobal.mod_func = SIZE_UNREAD; 
	else if (str_n_cmp(flag_arg, "--ru", 4) == 0) kmesglobal.mod_func = READ_UNREAD;
	else if (str_n_cmp(flag_arg, "--ce", 4) == 0) kmesglobal.mod_func = CONSOLE_ON;
	else if (str_n_cmp(flag_arg, "--cd", 4) == 0) kmesglobal.mod_func = CONSOLE_OFF;
	
	if (kmesglobal.mod_func) return;

	int offset = 4;
	if (str_n_cmp(flag_arg, "--R=", 4) == 0) kmesglobal.mod_func = READ;
	else if (str_n_cmp(flag_arg, "--L=", 4) == 0) kmesglobal.mod_func = CONSOLE_LEVEL;
	else if (str_n_cmp(flag_arg, "--ra=", 5) == 0) kmesglobal.mod_func = READ_ALL, offset++;
	else if (str_n_cmp(flag_arg, "--rc=", 5) == 0) kmesglobal.mod_func = READ_CLEAR, offset++;
	else {
		kmesglobal.mod_func = INVALID_FLAG;
		KMESG_ERR("invalid flag: '%s'.\n", flag_arg);
		return;
	}
	
	if (kmesglobal.mod_func == READ || kmesglobal.mod_func == READ_ALL || kmesglobal.mod_func == READ_CLEAR) {
		if ((kmesglobal.kern_msg_buf_size = str_to_int(flag_arg + offset)) < 0) {
			kmesglobal.mod_func = INVALID_FLAG;
			return;
		}
	} else if (kmesglobal.mod_func == CONSOLE_LEVEL) {
		if ((kmesglobal.log_level = str_to_int(flag_arg + offset)) < 0) {
			kmesglobal.mod_func = INVALID_FLAG;
			return;
		} else if (kmesglobal.log_level > 8 || kmesglobal.log_level < 1) {
			kmesglobal.mod_func = INVALID_FLAG;
			KMESG_ERR("invalid log level: %d, log levels must be in interval [1..8].\n", kmesglobal.log_level);
			return;
		}
	} 
	
	return;
}

void read_flag(char* flag_arg) {
	unsigned int arg_len = str_len(flag_arg);
	if (str_cmp(flag_arg, "--no-color") == 0) {
		kmesglobal.flag_modes |= DISABLE_COLORS;
		return;
	} else if (str_n_cmp(flag_arg, "--dump=", 7) == 0) {
		kmesglobal.flag_modes |= DUMP_KMESG;
		mem_cpy(kmesglobal.dump_file_path, flag_arg + 7, MIN(MAX_DUMP_FILE_PATH_SIZE, arg_len - 7));
		return;
	} else if (str_n_cmp(flag_arg, "--dump-offset=", 14) == 0) {
		mem_cpy(kmesglobal.dump_offset, flag_arg + 14, MIN(MAX_DUMP_OFFSET_LEN, arg_len - 14));
		return;
	} else if (str_n_cmp(flag_arg, "--s=", 4) == 0) {
		if ((kmesglobal.min_severity = str_to_int(flag_arg + 4)) < 0) kmesglobal.mod_func = INVALID_FLAG;
		return;
	} else if (str_n_cmp(flag_arg, "--f=", 4) == 0) {
		if ((kmesglobal.min_facility = str_to_int(flag_arg + 4)) < 0) kmesglobal.mod_func = INVALID_FLAG;
		return;
	} else if (str_n_cmp(flag_arg, "--h", 3) == 0) {
		kmesglobal.mod_func = HELPER;
		return;
	} else if (str_n_cmp(flag_arg, "--rv", 4) == 0) {
		kmesglobal.flag_modes |= REVERSE_MODE;
		return;
	} else if (str_n_cmp(flag_arg, "--cl", 4) == 0) {
		kmesglobal.flag_modes |= LESS_MODE;
		return;
	}

	if (!kmesglobal.mod_func) check_mod_func_flag(flag_arg);
	else {
		kmesglobal.mod_func = INVALID_FLAG;
		KMESG_ERR("invalid flag: '%s'.\n", flag_arg);
		return;
	}

	return;
}

int exec_mod_func(void) {
	if (kmesglobal.mod_func == READ || kmesglobal.mod_func == READ_ALL || kmesglobal.mod_func == READ_CLEAR || kmesglobal.mod_func == READ_UNREAD) {
		if (!kmesglobal.kern_msg_buf_size && (kmesglobal.mod_func == READ_ALL || kmesglobal.mod_func == READ_CLEAR)) {
			if ((kmesglobal.kern_msg_buf_size = klogctl(SIZE_BUFFER, NULL, 0)) < 0) {
				kmesg_perror("failed to execute the function: " CRITICAL_COLOR "SIZE_BUFFER" RESET_COLOR ", because: ");
				return -1;
			}
		} else if (kmesglobal.mod_func == READ_UNREAD) { 
			if ((kmesglobal.kern_msg_buf_size = klogctl(SIZE_UNREAD, NULL, 0)) < 0) {
				kmesg_perror("failed to execute the function: " CRITICAL_COLOR "SIZE_UNREAD" RESET_COLOR ", because: ");
				return -1;
			}
			kmesglobal.mod_func = READ; // Change the mod func to READ, to execute the READ command, as part of the READ_UNREAD command
		} else if (!kmesglobal.kern_msg_buf_size) kmesglobal.kern_msg_buf_size = DEFAULT_MSG_BUF_SIZE;
		
		if (kmesglobal.flag_modes & LESS_MODE) printf("\033[?1049h"); // Switch to the alternate screen buffer
		printf(KMESG_COLOR "KMESG:" RESET_COLOR " the buffer size is set to \'%d\' bytes.\n", kmesglobal.kern_msg_buf_size);	

		char* msg_buff = (char*) calloc(kmesglobal.kern_msg_buf_size, sizeof(char));
		if (msg_buff == NULL) {
			KMESG_ERR("failed to allocate the msg buffer.\n");
			return -1;
		}

		int ret = 0;
		if ((ret = klogctl(kmesglobal.mod_func, msg_buff, kmesglobal.kern_msg_buf_size)) < 0) {
			SAFE_FREE(msg_buff);
			kmesg_perror("failed to execute the function: " CRITICAL_COLOR "%s" RESET_COLOR ", because: ", mod_func_names[kmesglobal.mod_func]);
			return -1;
		}

		print_kmsg(msg_buff, ret);
		SAFE_FREE(msg_buff);
		if (kmesglobal.flag_modes & LESS_MODE) printf("\033[?1049l"); // Restore the primary screen buffer

	} else if (kmesglobal.mod_func == CLEAR || kmesglobal.mod_func == CONSOLE_ON || kmesglobal.mod_func == CONSOLE_OFF || kmesglobal.mod_func == SIZE_UNREAD || kmesglobal.mod_func == CONSOLE_LEVEL) {
		int ret = 0;
		if (kmesglobal.mod_func == CONSOLE_LEVEL) ret = klogctl(kmesglobal.mod_func, NULL, kmesglobal.log_level);
		else ret = klogctl(kmesglobal.mod_func, NULL, 0);
		
		if (ret < 0) {
			kmesg_perror("failed to execute the function: " CRITICAL_COLOR "%s" RESET_COLOR ", because: ", mod_func_names[kmesglobal.mod_func]);
			return -1;
		}

		if (kmesglobal.mod_func == SIZE_UNREAD) printf("The number of bytes currently available to be read from the kernel log buffer is: %d.\n", ret);	
		else printf("Operation: " CRITICAL_COLOR "%s" RESET_COLOR " executed successfully.\n", mod_func_names[kmesglobal.mod_func]);	

	} else if (kmesglobal.mod_func == COLOR_DEMO) print_color_demo();

	return 0;
}

int main(int argc, char* argv[]) {
	if (argc > 1) {
		unsigned int arg_cnt = 0;
		argc--;
		while (arg_cnt++, argc--) {
			read_flag(argv[arg_cnt]);
			if (kmesglobal.mod_func == INVALID_FLAG) return -1;
		}
	}

	if (!kmesglobal.mod_func) kmesglobal.mod_func = READ_ALL;
	
	int err = 0;
	if (kmesglobal.mod_func == HELPER) print_helper();
	else if (kmesglobal.mod_func == COLOR_DEMO) print_color_demo();
	else if (kmesglobal.mod_func == LIST_LEVELS) print_list_levels();
	else err = exec_mod_func();

   	return err;
}

