//****IZP 2021/22: Projeсt 1****
//*Vladyslav Kovalets, xkoval21*

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

//Real password length + 3.
#define max_length_password 103
//Ascii 32-126 -> 95 + 2.
#define max_length_unique_symbol 97
#define HELP -1

typedef struct{
	unsigned int level;
	long unsigned parameter;
	bool stats_flag;
	bool help_flag;
	unsigned int error;
}Arguments;

typedef struct{
	char unique[max_length_unique_symbol];
	int current_index;
	unsigned int length;
}Unique;

typedef struct{
	unsigned int min;
}Mininum;

typedef struct{
	float avg;
	float passwords_count;
	unsigned int length;
}Average;

typedef enum{
	SWITCH_ARG_ERROR = 1,
	NEGATIVE_NUM_ERROR,
	LEVEL_ERROR,
	PARAMETER_ERROR,
	ARG_ERROR,
	ARGS_MORE_ERROR,
	ARGS_FEW_ERROR,
	LONG_PASSWORD_ERROR,
	ONLY_SWITCH_ERROR
}Errors;

int command_line_process(int argc, char * argv[], Arguments * args);
bool stdin_process(unsigned int level, long unsigned parameter, bool stats_flag);
void passed_passwords(char passwords[max_length_password], unsigned int level, long unsigned parameter);
void print_error(char * argv[], int error, Arguments * args);

bool first_level(char passwords[max_length_password]); 
bool second_level(char passwords[max_length_password], long unsigned parameter);
bool third_level(char passwords[max_length_password], long unsigned parameter);
bool fourth_level(char passwords[max_length_password], long unsigned parameter);

bool first_group(char passwords[max_length_password]);
bool second_group(char passwords[max_length_password]);
bool third_group(char passwords[max_length_password]);
bool fourth_group(char passwords[max_length_password]);

void stats_uniq(char passwords[max_length_password], unsigned int length, Unique * unique, Unique * black_list);
void stats_min(unsigned int length, Mininum * shortest);
void stats_avg(float password_length, Average * average);
bool check_blacklist(char c, Unique * black_list);

void struct_arguments(Arguments * args);
void struct_statistics(Unique * array_unique, Unique * array_blacklist, Mininum * shortest, Average * average);
bool check_level(unsigned int level);
bool check_parameter(long unsigned parameter);
int symbols_count(char passwords[max_length_password]);
bool cmp(char *str1, char *str2);
bool is_digit(char array[]);
void print_stats(unsigned int min, float avg, unsigned int unique_symbols);
void print_help_string(void);

int main(int argc, char * argv[])
{	
	//Variables for arguments.
	Arguments args;
	struct_arguments(&args);

	int is_error = command_line_process(argc, argv, &args);

	//Works with errors.
	if (is_error != EXIT_SUCCESS)
	{
		print_error(argv, is_error, &args);		
		return EXIT_FAILURE;
	}
	else if (is_error == HELP)
		return EXIT_SUCCESS;

	//Handles stdin.
	if (stdin_process(args.level, args.parameter, args.stats_flag) == EXIT_FAILURE)
		return EXIT_FAILURE;
	
	return EXIT_SUCCESS;
}

//Handles command line.
int command_line_process(int argc, char * argv[], Arguments * args)
{	
	//The switch wasn't activated.
	bool switch_flag = false;
	if (argc > 6)
		return ARGS_MORE_ERROR;
	//Reads command line arguments.
	for(int i = 1; i < argc; i++)
	{
		//Checks for switches and processes them.
		if(argv[i][0] == '-')
		{
			switch_flag = true;
			switch(argv[i][1])
			{		
			case 'l' :
				if (argv[i+1] == NULL)
					return ONLY_SWITCH_ERROR;
				else if (atoi(argv[i+1]) > 0)
				{
					args->level = atoi(argv[i+1]);
					i++;
				}
				else return SWITCH_ARG_ERROR;
				break;

			case 'p' :
				if (argv[i+1] == NULL)
					return ONLY_SWITCH_ERROR;
				else if (atoi(argv[i+1]) > 0)
				{
					args->parameter = atoi(argv[i+1]);
					i++;
				}
				else return SWITCH_ARG_ERROR;
				break;

			case 'h' :
				if (cmp("-h", argv[i]))
				{
					print_help_string();
					return HELP;
				}
				args->error = i;
				return ARG_ERROR;
				
			default :
				//Checks if statistics are required.
				if (cmp("--stats", argv[i]))	
					args->stats_flag = 1;
				else if ((strtol(argv[i], NULL, 10)) < 0)
					return NEGATIVE_NUM_ERROR;
				else
				{
					args->error = i;
					return ARG_ERROR;
				}
			}
		}
		//If without switches.
		else 
		{
			if (argc > 4)
				return ARGS_MORE_ERROR;
			else if ((argc == 2) || (switch_flag == 1 && argc < 5)) 
				return ARGS_FEW_ERROR;
			else if (strtol(argv[2], NULL, 10) < 0)
				return NEGATIVE_NUM_ERROR;

			if (is_digit(argv[1]))
				args->level = atoi(argv[1]);
			else
			{
				args->error = i;
				return ARG_ERROR;
			}

			if (is_digit(argv[2]))
			{
				args->parameter = atoi(argv[2]);
				i++;
			}
			else 
			{
				args->error = i+1;
				return ARG_ERROR;
			}
		}
	}

	if (switch_flag == false && argc > 3)
	{
		args->error = 3;
		return ARG_ERROR;
	}

	if ((args->stats_flag == false && argc > 5) || (switch_flag == false && argc > 4)) 
		return ARGS_MORE_ERROR;

	if (!check_level(args->level))
		return LEVEL_ERROR;
	else if (!check_parameter(args->parameter))
		return PARAMETER_ERROR;

	return 0;
}

//Handles stdin.
bool stdin_process(unsigned int level, unsigned long parameter, bool stats_flag)
{
	//Array for stdin data.
	char passwords[max_length_password];	
	unsigned int length_password = 0;

	//Variables for statistics.
	Unique array_unique; 
	Unique array_blacklist;
	Mininum shortest;
	Average average;
	struct_statistics(&array_unique, &array_blacklist, &shortest, &average);
	
	while (fgets(passwords, max_length_password, stdin)) 
	{	
		length_password = symbols_count(passwords);
		//Real password length = max_length_password - 3.
		if (length_password > max_length_password - 3) 
		{
			print_error(NULL, LONG_PASSWORD_ERROR ,NULL);
			return EXIT_FAILURE;
		}
		passed_passwords(passwords, level, parameter);
		//Calculates statistics if required.
		if(stats_flag && length_password != 0)
		{
			stats_min(length_password, &shortest);
			stats_avg(length_password, &average);
			stats_uniq(passwords, length_password, &array_unique, &array_blacklist);
		}
	}
	//Displays statistics if required.
	if(stats_flag)
		print_stats(shortest.min, average.avg, symbols_count(array_unique.unique));

	return 0;
}

//Passed passwords will be printed.
void passed_passwords(char passwords[max_length_password], unsigned int level, long unsigned parameter)
{
	//Added to improve code readability.
	bool first = first_level(passwords);
	bool second = second_level(passwords, parameter);
	bool third = third_level(passwords, parameter);
	bool fourth = fourth_level(passwords, parameter);

	switch (level)
	{
	case 1:
		if (first)
			printf("%s", passwords);
		break;
	case 2:
		if (first && second)
			printf("%s", passwords);
		break;
	case 3:
		if (first && second && third)
			printf("%s", passwords);
		break;
	case 4:
		if (first && second && third && fourth) 
			printf("%s", passwords);
		break;
	}
}

//Checks a string considering the first and second groups.
bool first_level(char passwords[max_length_password])
{
	if (first_group(passwords) && second_group(passwords)) 
		return true;
	else return false;
}

//Checks a string considering groups.
bool second_level(char passwords[max_length_password], long unsigned parameter)
{
	//If the parameter is greater than 4, then all(4) groups are checked.
	if (parameter > 4)
		parameter = 4;
	
	unsigned int i = 0;
	while (i != parameter)
	{
		if (first_group(passwords) == true)
			i++;	
		if (second_group(passwords) == true)
			i++;
		if (third_group(passwords) == true)
			i++;
		if (fourth_group(passwords) == true)
			i++;
		break;
	}
	if (i >= parameter)
		return true;
	else return false;
}

//Checks a string considering it doesn't contain the same sequence of characters at least "parameter".
bool third_level(char passwords[max_length_password],long unsigned parameter)
{
	//If the parameter is 1, then the password doesn't pass. For optimization.
	if (parameter == 1)
		return false;

	unsigned int length = symbols_count(passwords);
	unsigned int count = parameter;
	
	for (unsigned int i = 0; i < length; i++)
	{
		//Checks if characters are equal
		if((passwords[i]) == passwords[i+1])
		{
			count--;
			//If "count" is equal to one, then password contain the same sequence of characters at least "parameter".
			if (count == 1)
				return false;
		}
		//Resets the counter to its initial value.
		else count = parameter;
	} 
	return true;
}

//Checks a string considering it doesn't contain two identical substrings of at least "parametr" characters. 
bool fourth_level(char passwords[max_length_password], long unsigned parameter) 
{
	//If the parameter is 1, then the password doesn't pass. For optimization.
	if (parameter == 1)
		return false;

	unsigned int length = symbols_count(passwords);
	long unsigned count = parameter;
	//Indexes for comparison.
	unsigned int i, j; 
	//It's for checkpoints.
	unsigned int save_i = 0;
  	unsigned int save_j = 0;
  	bool save = 1;
	
	for (i = 0, j = 1; i < length; j++)
	{	
		//Checks if characters are equal.
		if((passwords[i]) == passwords[j])	
		{
			//Makes a checkpoint.
			if (save == 1) 
      		{
        		save_i = i;
        		save_j = j;
        		save = 0;
      		}
			count--;
			i++;
			//If "count" is equal to one, then password contain two identical substrings of at least "parametetr" characters.
			if (count == 0)
				return false;
		}
		else if (j == length)
		{
			j = i + 1;
			i++;
		}
		else{
			//Resets the counter to its initial value.
			count = parameter;
			//Recovers values from a checkpoint.
			 if (save == 0)
			{  
				i = save_i;
				j = save_j;
				save = 1;
			}
		}
	}
	return true;
}

//Checks a string for lowercase letters
bool first_group(char passwords[max_length_password])
{
	unsigned int length = symbols_count(passwords);
	for (int unsigned i = 0; i < length; i++)
	{
		if (passwords[i] >= 'a' && passwords[i] <= 'z') 
			return true;
	} 
	return false;
}

//Checks a string for uppercase letters
bool second_group(char passwords[max_length_password])
{
	unsigned int length = symbols_count(passwords);
	for (unsigned int i = 0; i < length; i++)
	{
		if (passwords[i] >= 'A' && passwords[i] <= 'Z') 
			return true;
	} 
	return false;
}

//Checks a string for digits.
bool third_group(char passwords[max_length_password])
{
	unsigned int length = symbols_count(passwords);
	for (unsigned int i = 0; i < length; i++)
	{
		if (passwords[i] >= '0' && passwords[i] <= '9') 
			return true;
	} 
	return false;
}

//Checks a string for special characters(Unique 32-126).
bool fourth_group(char passwords[max_length_password])
{
	unsigned int length = symbols_count(passwords);
	for (unsigned int i = 0; i < length; i++)
	{
		char symbol = passwords[i];
		if ((symbol >= ' ' && symbol <= '/') || (symbol >= ':' && symbol <= '@') ||
		    (symbol >= '[' && symbol <= '`') || (symbol >= '{' && symbol <= '~')) 
			return true;
	} 
	return false;
}

//Calculates the number of unique characters.
void stats_uniq(char passwords[max_length_password], unsigned int length, Unique * unique, Unique * black_list)
{	
	//Checks all characters in a string.
	for(unsigned int i = 0; i <= length; i++)
	{
		//Writes the first unique character to an array.
		if (unique->current_index == -1) //if array is empty
			{
				unique->current_index++;
				unique->unique[unique->current_index] = passwords[i]; 
				unique->length++;

				black_list->current_index++;
				black_list->unique[black_list->current_index] = passwords[i];
				black_list->length++;
			}
		//Checks if a character isn't unique.
		else if (check_blacklist(passwords[i], black_list)) //comparing symbols  
				continue;
		//Writes next unique characters to an array.
		else
		{
			unique->current_index++;
			unique->unique[unique->current_index] = passwords[i];
			unique->length++;

			black_list->current_index++;
			black_list->unique[black_list->current_index] = passwords[i];
			black_list->length++;
		}
	}
	//Ends a line.
	unique->unique[unique->current_index + 1] = '\0';
}

//Checks if a character is in an array.
bool check_blacklist(char c, Unique * black_list)
{
	for(unsigned int i = 0; i < black_list->length; i++)
	{
		if (c == black_list->unique[i])
			return true;
	}
	return false;
}

//Calculates the minimum number of characters.
void stats_min(unsigned int length, Mininum * shortest)
{
	if (shortest->min == 0 || shortest->min > length)
		shortest->min = length;
}

//Calculates the average number of characters.
void stats_avg(float password_length, Average * average)
{
	average->length += password_length;
	average->passwords_count++;
	average->avg = average->length / average->passwords_count;
}

//Counting the number of required elements in string. 
int symbols_count(char passwords[max_length_password])
{
	unsigned int i = 0;
	//Until end-of-line character is encountered.
	while (passwords[i] != '\0') 
	{
		i++;
	}
	//Besides the line break character(\n).
	return i - 1;
}

//Compares strings.
bool cmp(char *str1, char *str2)
{
	unsigned int i = 0;
	while (str1[i] == str2[i] && str1[i] != '\0')
    	i++;
	if (str1[i] == str2[i])
    	return true;
	else 
		return false;
}

//Checks if all characters in an array are numbers.
bool is_digit(char array[])
{
    for (int i = 0; i <= symbols_count(array); i++)
    {
        if (!((int)array[i] >= 48 && (int)array[i] <= 57))
           return false;  
    }
	return true;
}

//Checks the validity of the data in the level.
bool check_level(unsigned int level)
{
	if (level > 0 && level < 5)
		return true;
	return false;
}

//Checks the validity of the data in the parameter.
bool check_parameter(long unsigned parameter)
{
	if (parameter != 0) 
		return true;
	return false;
}

//Initialization of the arguments structure.
void struct_arguments(Arguments * args)
{
	args->level = 1;
	args->parameter = 1;
	args->stats_flag = 0;
	args->help_flag = 0;
	args->error = 0;
}

//Initialization of the statistics structure.
void struct_statistics(Unique * array_unique, Unique * array_blacklist, Mininum * shortest, Average * average)
{
	array_unique->unique[0] = '\n';
	array_unique->unique[1] = '\0';
	array_unique->current_index = -1;
	array_unique->length = 0;

	array_blacklist->current_index = -1;
	array_blacklist->length = 0;

	shortest->min = 0;

	average->avg = 0;
	average->passwords_count = 0;
	average->length = 0;
}

//Prints statistics.
void print_stats(unsigned int min, float avg, unsigned int unique_symbols)
{
	printf("Statistika:\n"
			"Ruznych znaku: %u\n"
			"Minimalni delka: %u\n"
			"Prumerna delka: %.1f\n", unique_symbols, min, avg);
}

//Prints error messages.
void print_error(char * argv[], int error, Arguments * args)
{
	fprintf(stderr, "Error. You entered incorrect values. Use \"-h\" for help.\n");
	
	if 		(error == SWITCH_ARG_ERROR)    fprintf(stderr, "Don't use characters, negative numbers or zero with \"-l\" or \"-p\".\n");
	else if (error == NEGATIVE_NUM_ERROR)  fprintf(stderr, "LEVEL or PARAM cannot be negative numbers.\n");
	else if (error == LEVEL_ERROR)         fprintf(stderr, "Level out of range [1,4].\n");
	else if (error == PARAMETER_ERROR)     fprintf(stderr, "The parameter cannot be zero.\n");
	else if (error == ARG_ERROR) 	       fprintf(stderr, "Unknown argument \"%s\".\n",argv[args->error]);
	else if (error == ARGS_MORE_ERROR)     fprintf(stderr, "Too many arguments.\n");
	else if (error == ARGS_FEW_ERROR)      fprintf(stderr, "Too few arguments.\n");
	else if (error == LONG_PASSWORD_ERROR) fprintf(stderr, "Password length cannot exceed 100 characters.\n");
	else if (error == ONLY_SWITCH_ERROR)   fprintf(stderr, "Use argument after \"-l\" or \"-p\".\n");
}

//Prints help.
void print_help_string(void)
{
	printf("The program receives passwords and checks each one for the necessary rules.\n" 
			"Passwords that have been verified will be displayed.\n\n"
			"The program runs in the following forms:\n"
			"./pwcheck LEVEL PARAM [--stats] or ./pwcheck [-l LEVEL] [-p PARAM] [--stats]\n"
			"When using additional switches, the program does not require arguments only in fixed positions.\n\n"
			"LEVEL   - is an integer in the interval [1, 4] that specifies the required security level.\n"
			"PARAM   - is a positive integer that specifies an additional rule parameter.\n"
			"--stats - if specified, statistics of the analyzed passwords will be displayed.\n\n"
			"LEVELs and PARAMs\n"
			"The security level specifies that passwords must comply with all rules at that and lower levels.\n"
			"LEVEL 1: The password contains at least 1 uppercase and 1 lowercase letter.\n"
			"LEVEL 2: The password contains characters from at least PARAM groups.\n"
			"         Groups:\n"
			"                * lowercase letters (a-z)\n"
			"                * uppercase letters (A-Z)\n"
			"                * numbers (0-9)\n"
			"                * special characters (Unique 32-126)\n"
			"LEVEL 3: The password does not contain the same sequence of characters of at least PARAM.\n"
			"LEVEL 4: The password does not contain two identical substrings of at least PARAM.\n\n"
			"Statistics include:\n"
			"                   - number of different characters found in all passwords\n"
			"                   - length of the shortest password\n"			
			"                   - average password length\n"
			"Statistics include all passwords.\n\n"
			"Details\n"
			"The password is entered on a separate line.\n"
			"Contains only Unique characters, except newline character.\n"
			"The maximum length of the password is 100 characters, otherwise it is invalid data.\n" 
			"The program supports an unlimited number of passwords.\n");		
}