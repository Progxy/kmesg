#include <stdio.h>
#include <stdlib.h>
#include <sys/klog.h>
#include <errno.h>
#include <string.h>

#define CHR_TO_INT(chr) ((int)chr - 48)
#define IS_A_VAL(chr) (chr >= 48 && chr <= 57)

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

int str_to_int(char* str) {
	unsigned int value = 0;
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
			for (unsigned int i = 0; i < *lines_cnt - 1; ++i) free(lines[*lines_cnt]);
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

void print_line(char* str_line) {
	// Line example "<log_level_num> [timestamp] info..."
	unsigned int len = str_len(str_line);
	unsigned int str_pos = 1;

	// Extract the log level is composed by severity and facility (combined value = (facility x 8) + severity), in this way we can filter messages by facility and severity
	long long int log_level_end_pos = find_chr(str_line + str_pos, len - str_pos, '>');
	if (log_level_end_pos < 0) {
		KMESG_ERR("invalid string format: '%s'.\n", str_line);
		return;
	}
	
	char* log_level_str = (char*) calloc(log_level_end_pos + 1, sizeof(char));
	if (log_level_str == NULL) {
		KMESG_ERR("failed to allocate the log level buf.\n");
		return;
	}
	mem_cpy(log_level_str, str_line + str_pos, log_level_end_pos);
	log_level_str[log_level_end_pos] = '\0';
	str_pos += log_level_end_pos + 1;

	unsigned int log_level = str_to_int(log_level_str);
	unsigned int facility = log_level / 8;
	unsigned int severity = log_level % 8;
	free(log_level_str);

	if (severity > min_severity || facility > min_facility) {
		return;
	}

	// Extract the timestamp
	long long int timestamp_end_pos = find_chr(str_line + str_pos, len - str_pos, ']');
	if (timestamp_end_pos < 0) {
		KMESG_ERR("invalid string format: '%s'.\n", str_line);
		return;
	} 

	char* timestamp = (char*) calloc(timestamp_end_pos + 2, sizeof(char));
	if (timestamp == NULL) {
		KMESG_ERR("failed to allocate the timestamp buff.\n");
		return;
	}
	mem_cpy(timestamp, str_line + str_pos, timestamp_end_pos + 1);
	timestamp[timestamp_end_pos + 1] = '\0';
	str_pos += timestamp_end_pos + 1;

	// Extract the module defined identifier, we check for the pos of the column (like "MODULE-NAME_LOG-LEVEL: ...")
	long long int column_ref = find_chr(str_line + str_pos, len - str_pos, ':');
	// Print the rest if the identifier is not present
	if (column_ref < 0) {
		printf(TIMESTAMP_COLOR "%s" RESET_COLOR "%s\n", timestamp, (str_line + str_pos));
		return;
	}
	
	char* module_identifier = (char*) calloc(column_ref + 2, sizeof(char)); 
	if (module_identifier == NULL) {
		free(timestamp);
		printf("failed to allocate module_identifier.\n");
		return;
	}

	mem_cpy(module_identifier, str_line + str_pos, column_ref + 1);
	module_identifier[column_ref + 1] = '\0';
	str_pos += column_ref + 1;

	printf(TIMESTAMP_COLOR "%s" RESET_COLOR "%s%s" RESET_COLOR "%s\n", timestamp, log_level_colors[severity], module_identifier, (str_line + str_pos));

	free(timestamp);
	free(module_identifier);

	return;
}

void print_kmsg(char* kmesg, unsigned int len) {
	printf(KMESG_COLOR "KMESG: " RESET_COLOR "Read %d bytes, messages in the kernel ring buffer: \n", len);
	// Extract the lines and then process each one of them
	unsigned int lines_cnt = 0;
	char** lines = extract_lines(kmesg, len, &lines_cnt);
	if (lines == NULL || !lines_cnt) return; 
	for (unsigned int i = 0; i < lines_cnt; ++i) {
		print_line(lines[i]);
		free(lines[i]);
	}
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
	printf("\t-ce: Set the console log level to the default, so that messages are printed to the console.\n");
	printf("\t-cd: Set the console log level to the minimum, so that no messages are printed to the console.\n");
	printf("\t-L:  Set the console log level to the value passed after the flag, which must be an integer between 1 and 8 (inclusive).\n");
	printf("\t-s:  Set the MIN_SEVERITY using the value passed after the flag. The default value is '%s'.\n", severities_names[min_severity]);
	printf("\t-f:  Set the MIN_FACILITY using the value passed after the flag. The default value is '%s'.\n", facilities_names[min_facility]);
	printf("\t-l:  List SEVERITY levels and FACILITY levels.\n");
	printf("\t-h:  Show this page.\n");
	printf("\n" EMERGENCY_COLOR "KMESG: " DEBUG_COLOR "A colored alternative to " NOTICE_COLOR "dmesg" WARNING_COLOR ", by" KMESG_COLOR " \'TheProgxy\'." RESET_COLOR"\n");
	return; 
}

void read_flag(char* flag_arg) {
	unsigned int arg_len = str_len(flag_arg);
	if (!mod_func) {
		if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'C') mod_func = CLEAR; 
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'R') mod_func = READ;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'u') mod_func = SIZE_UNREAD; 
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'd') mod_func = COLOR_DEMO;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'a') mod_func = READ_ALL;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'c') mod_func = READ_CLEAR;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'r' && flag_arg[2] == 'u') mod_func = READ_UNREAD;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'c' && flag_arg[2] == 'e') mod_func = CONSOLE_ON;
		else if (arg_len > 2 && flag_arg[0] == '-' && flag_arg[1] == 'c' && flag_arg[2] == 'd') mod_func = CONSOLE_OFF;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'L') mod_func = CONSOLE_LEVEL;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'l') mod_func = LIST_LEVELS;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'h') mod_func = HELPER;
		else {
			mod_func = INVALID_FLAG;
			KMESG_ERR("invalid flag: '%s'\n.", flag_arg);
			return;
		}
	} else {
		if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 's') mod_func = SET_MIN_SEVERITY;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'f') mod_func = SET_MIN_FACILITY;
		else if (arg_len > 1 && flag_arg[0] == '-' && flag_arg[1] == 'h') mod_func = HELPER;
		else {
			mod_func = INVALID_FLAG;
			KMESG_ERR("invalid flag: '%s'\n.", flag_arg);
			return;
		}
	}
	
	if (mod_func == HELPER || mod_func == LIST_LEVELS || mod_func == COLOR_DEMO) return;
	
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
	} else if (mod_func == SET_MIN_SEVERITY || mod_func == SET_MIN_FACILITY) {
		long long int value_pos = find_chr(flag_arg, arg_len, '=');
		if (value_pos < 0) return;
		int value = str_to_int(flag_arg + value_pos + 1);
		if (value < 0) {
			mod_func = INVALID_FLAG;
			return;
		}
		if (mod_func == SET_MIN_SEVERITY) min_severity = value;
		else min_facility = value;
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
