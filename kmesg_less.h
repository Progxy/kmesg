/*
 * Copyright (C) 2025 TheProgxy <theprogxy@gmail.com>
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

#ifndef _KMESG_LESS_H_
#define _KMESG_LESS_H_

#include <termcap.h>
#include <termios.h>

/* -------------------------------------------------------------------------------------------------------- */
// --------------------------------
//  Structures and Constant Values
// --------------------------------
#define MAX_SEARCH_BUF_SIZE 256
#define MAX_LINE_MATCH_BUF_SIZE 12

typedef struct KMESGTerm {
	char* clear_cmd;
	long long int term_height;
	struct termios original_settings;
} KMESGTerm;

/* -------------------------------------------------------------------------------------------------------- */
// ------------------ 
//  Static Variables
// ------------------ 
static KMESGTerm kmesg_term = {0};

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
bool print_line(char* str_line); // Reference the function defined in kmesg.c

/* -------------------------------------------------------------------------------------------------------- */
// -----------------------
//  Functions Definitions
// -----------------------
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

bool print_screen(long long int start_line, char** lines, long long int lines_cnt) {
	printf("%s", kmesg_term.clear_cmd); 
	
	for (long long int i = start_line, j = 0; (j < kmesg_term.term_height) && (i < lines_cnt); ++i, ++j) {
		if (i < 0) {
			printf("\n");
			continue;
		}

		if (!print_line(lines[i])) {
			disable_raw_mode(kmesg_term.original_settings);
			return FALSE;
		}
	}

	printf(KMESG_COLOR "KMESG: " RESET_COLOR "Line %lld out of %lld (%u%%)\n:", start_line + kmesg_term.term_height, lines_cnt, (unsigned int) (((float)(start_line + kmesg_term.term_height) / lines_cnt) * 100.0f));
	fflush(stdout);

	return TRUE;
}

void echo_char(char c) {
	if (c == 127 || c == 8) printf("\b \b");
	else printf("%c", c);
	fflush(stdout);
	return;
}

int find_substr_in_lines(unsigned int** list, unsigned int* size, const char* sub_str, char** lines, long long int lines_cnt) {
	unsigned int sub_str_size = str_len(sub_str);
	for (long long int i = 0; i < lines_cnt; ++i) {
		unsigned int line_size = str_len(lines[i]);
		for (unsigned int j = 0; j < line_size - sub_str_size; ++j) {
			if (str_n_cmp(sub_str, lines[i] + j, sub_str_size) == 0) {
				*list = realloc(*list, sizeof(unsigned int) * (++(*size)));
		
				if (*list == NULL) {
					KMESG_ERR("Failed to reallocate buffer for list.\n");
					return FALSE;
				}
		
				(*list)[*size - 1] = i;
		
				break;
			}
		}
	}
	
	return TRUE;
}

// TODO: At some point would be probably cool to also have a bit of regex support
void less_search(long long int* start_line, char** lines, long long int lines_cnt) {
	char c = 0;
	unsigned int buf_index = 0;
	char buf[MAX_SEARCH_BUF_SIZE] = {0}; 
	
	while(read(STDIN_FILENO, &c, 1) == 1) {
		if (c == 27) {
			print_screen(*start_line, lines, lines_cnt);
			return;
		} else if (c == '\n') break;
		echo_char(c); 
		
		if (c == 127 || c == 8) {
			if (buf_index == 0) return;
			buf[--buf_index] = '\0';
		}
		
		buf[buf_index++] = c;
		if (buf_index == MAX_SEARCH_BUF_SIZE) break;
	}

	unsigned int* search_list = NULL;
	unsigned int search_list_size = 0;
	unsigned int search_ind = 0;

	// Perform the search
	if (!find_substr_in_lines(&search_list, &search_list_size, buf, lines, lines_cnt)) return;

	*start_line = search_list[search_ind];
	if (!print_screen(*start_line, lines, lines_cnt)) {
		free(search_list);
		return;
	}

	if (search_list == NULL || search_list_size == 0) {
		printf("No match for ...");
		fflush(stdout);
		return;
	}
	
	printf("/%.*s", buf_index, buf);
	fflush(stdout);

	while(read(STDIN_FILENO, &c, 1) == 1) {
		if (c == '\n' || c == 27) break;
		else if (c == 'n') {
			search_ind = (search_ind + 1) % search_list_size;
			*start_line = search_list[search_ind];
		} else if (c == 'p') {
			search_ind = (search_ind - 1) % search_list_size;
			*start_line = search_list[search_ind];
		}
		
		if (!print_screen(*start_line, lines, lines_cnt)) {
			free(search_list);
			return;
		}
		
		printf("/%.*s", buf_index, buf);
		fflush(stdout);
	}

	if (!print_screen(*start_line, lines, lines_cnt)) {
		free(search_list);
		return;
	}
	
	free(search_list);

	return;
}

void line_match(char c, long long int* start_line, char** lines, long long int lines_cnt) {
	char buf[MAX_LINE_MATCH_BUF_SIZE] = {0};
	unsigned int buf_index = 0;
	buf[buf_index++] = c;
	
	while(read(STDIN_FILENO, &c, 1) == 1) {
		if (c == '\n') break;
		echo_char(c);

		// Shift the chars inside the buffer left
		if (IS_A_VAL(c)) {
			if (buf_index == 11) mem_cpy(buf, buf + 1, MAX_LINE_MATCH_BUF_SIZE - 1);
			buf[buf_index] = c;
			buf_index = (buf_index + 1) % MAX_LINE_MATCH_BUF_SIZE;
		} else if (c == 127 || c == 8) {
			if (buf_index > 0) buf[--buf_index] = '\0';
		}
	}

	if (buf_index) {
		long long int line = str_to_int(buf);
		if (line <= 0 || (line > lines_cnt)) {
			if (!print_screen(*start_line, lines, lines_cnt)) return;
			if (line < 0) KMESG_ERR(" Not a value: '%s'\n", buf);
			else if (line > lines_cnt || line == 0) KMESG_ERR(" Invalid value: %lld, it must be between 1 and %lld\n", line, lines_cnt);
			return;
		}

		*start_line = line - kmesg_term.term_height;
		if (!print_screen(*start_line, lines, lines_cnt)) return;
	} 

	return;
}

void check_movement(char c, long long int* start_line, char** lines, long long int lines_cnt) {
	if (c == 'g' || c == '<') *start_line = -kmesg_term.term_height + 1;
	else if (c == 'G' || c == '>') *start_line = lines_cnt - kmesg_term.term_height;
	else if ((c == 'j') && (*start_line < lines_cnt - kmesg_term.term_height)) (*start_line)++; 
	else if ((c == 'k') && (*start_line > -kmesg_term.term_height + 1)) (*start_line)--;
	else if ((c == ' ') && (*start_line < lines_cnt - kmesg_term.term_height)) {
		*start_line += kmesg_term.term_height; 
		*start_line = MIN(*start_line, lines_cnt - kmesg_term.term_height);
	} else if ((c == 'b') && (*start_line > -kmesg_term.term_height + 1)) {
		*start_line -= kmesg_term.term_height;
		*start_line = MAX(*start_line, -kmesg_term.term_height + 1);
	} else if (c == '\033') {
		char seq[3] = {0};
		if (read(STDIN_FILENO, &seq[0], 1) == 0) return;
		else if (read(STDIN_FILENO, &seq[1], 1) == 0) return;
		else if (seq[0] != '[') return;
		
		if ((seq[1] == 'A') && (*start_line > -kmesg_term.term_height + 1)) (*start_line)--;
		else if ((seq[1] == 'B') && (*start_line < lines_cnt - kmesg_term.term_height)) (*start_line)++;
	}
	
	if (!print_screen(*start_line, lines, lines_cnt)) return;
	
	return;
}

// TODO: Should probably introduce the cursor to move around within the text.
//       And more generally other features that requires a moving cursor.
void print_less(char** lines, long long int lines_cnt) {
    char term_buffer[2048] = {0};
    if (tgetent(term_buffer, getenv("TERM")) <= 0) return;

    kmesg_term.clear_cmd = tgetstr("cl", NULL);
    kmesg_term.term_height = tgetnum("li") - 2;
    kmesg_term.original_settings = enable_raw_mode();

	// Init Screen
	long long int start_line = -kmesg_term.term_height + 1; 
	if (!print_screen(start_line, lines, lines_cnt)) return;
	
	char c = 0;
	while (read(STDIN_FILENO, &c, 1) == 1) {
		if (c == 'q') break;
		else if (IS_A_VAL(c)) {
			echo_char(c);
			line_match(c, &start_line, lines, lines_cnt);
			continue;
		} else if (c == '/') {
			echo_char(c);
			less_search(&start_line, lines, lines_cnt);
			continue;
		}

		check_movement(c, &start_line, lines, lines_cnt);
		
	}

    disable_raw_mode(kmesg_term.original_settings);
    
	return;

}

#endif //_KMESG_LESS_H_

