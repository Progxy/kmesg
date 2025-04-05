#ifndef _KMESG_UTILS_H_
#define _KMESG_UTILS_H_

typedef unsigned char bool;

#define MAX_DUMP_FILE_PATH_SIZE 512
#define DEFAULT_MSG_BUF_SIZE    8192
#define MAX_DUMP_OFFSET_LEN     20
#define MAX_DUMP_LINE_SIZE      512

#define FALSE 0
#define TRUE 1

#define CHR_TO_INT(chr) ((int)(chr) - 48)
#define IS_A_VAL(chr)   (((chr) >= 48) && ((chr) <= 57))
#define MAX(a, b)       ((a) > (b) ? (a) : (b)) 
#define MIN(a, b)       ((a) < (b) ? (a) : (b)) 

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

#define KMESG_ERR(fmt, ...)    printf(ERROR_COLOR "KMESG_ERROR" RESET_COLOR "(line: %u):" fmt, __LINE__, ##__VA_ARGS__)
#define kmesg_perror(fmt, ...) KMESG_ERR(fmt WARNING_COLOR "%s.\n" RESET_COLOR, ##__VA_ARGS__, strerror(errno))

#define KMESG_VERSION "1.2.0"

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

typedef enum FlagModes { 
	LESS_MODE      = 0x01,
	REVERSE_MODE   = 0x02,
	DISABLE_COLORS = 0x04,
	DUMP_KMESG     = 0x08
} FlagModes;

typedef struct KMESGlobal {
	unsigned int min_severity;
	unsigned int min_facility;
	unsigned char mod_func;
	int kern_msg_buf_size;
	int log_level;
	char dump_file_path[MAX_DUMP_FILE_PATH_SIZE];
	FILE* dump_file;
	char dump_offset[MAX_DUMP_OFFSET_LEN];
	FlagModes flag_modes;
} KMESGlobal;

// -----------------------
//  Functions Definitions
// -----------------------
unsigned int str_len(const char* str) {
	if (str == NULL) return 0;
	unsigned int i = 0;
	while (str[i] != '\0') ++i;
	return i;
}

static void mem_cpy(void* dest, const void* src, size_t size) {
	if (dest == NULL || src == NULL) return;
	for (size_t i = 0; i < size; ++i) ((unsigned char*) dest)[i] = ((unsigned char*)src)[i];
	return;
}

static void mem_set(void* dest, unsigned char val, size_t size) {
	if (dest == NULL) return;
	for (size_t i = 0; i < size; ++i) ((unsigned char*) dest)[i] = val;
	return;
}

unsigned int ref_chr_cnt(const char* str, unsigned int len, char chr) {
	unsigned int ref_cnt = 0;
	if (str == NULL) return 0;
	for (unsigned int i = 0; i < len; ++i) if (str[i] == chr) ref_cnt++;
	return ref_cnt;
}

long long int find_chr(const char* str, unsigned int len, char chr) {
	if (str == NULL) return -2;
	for (unsigned int i = 0; i < len; ++i) if (str[i] == chr) return (int) i;
	return -1;
}

long long int str_to_int(const char* str) {
	long long int value = 0;
	if (str == NULL) return 0;

	unsigned int i = 0;
	while (str[i] != '\0') {
		if (!IS_A_VAL(str[i])) {
			KMESG_ERR(" this is not a valid value: " CRITICAL_COLOR "'%s'" RESET_COLOR ".\n", str);
			return -1;
		}
	
		value = (value * 10) + CHR_TO_INT(str[i]);
		++i;
	}
	
	return value;
}

int str_cmp(const char* str1, const char* str2) {
    // Null Checks
    if (str1 == NULL && str2 == NULL) return 0;
    if (str1 == NULL) return -1;
    else if (str2 == NULL) return 1;

    size_t i = 0;
    while (str1[i] != '\0' || str2[i] != '\0') {
        if (str1[i] != str2[i]) return str1[i] - str2[i];
        ++i;
    }
    
	return 0;
}

int str_n_cmp(const char* str1, const char* str2, size_t n) {
    // Null Checks
    if (str1 == NULL && str2 == NULL) return 0;
    if (str1 == NULL) return -1;
    else if (str2 == NULL) return 1;

    size_t i = 0;
    while ((str1[i] != '\0' || str2[i] != '\0') && i < n) {
        if (str1[i] != str2[i]) return str1[i] - str2[i];
        ++i;
    }

	return 0;
}

void reverse_str_arr(char*** str_arr, unsigned int size) {
	for (unsigned int i = 0; i < (size >> 1); ++i) {
		char* temp = (*str_arr)[i];
		(*str_arr)[i] = (*str_arr)[size - 1 - i];
		(*str_arr)[size - 1 - i] = temp;
	}
	return;
}

#endif //_KMESG_UTILS_H_

