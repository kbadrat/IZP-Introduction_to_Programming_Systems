# Project 1 IZP (2021)

 Grade   | Bonus Points |
---------|--------------|
 10/10   | 0.8/1.0      |

The program receives passwords and checks each one for the necessary rules.
Passwords that have been verified will be displayed.

## The program runs in the following forms:
```/pwcheck LEVEL PARAM [--stats]``` or ```./pwcheck [-l LEVEL] [-p PARAM] [--stats]```

When using additional switches, the program does not require arguments only in fixed positions.
LEVEL   - is an integer in the interval [1, 4] that specifies the required security level.
PARAM   - is a positive integer that specifies an additional rule parameter.
--stats - if specified, statistics of the analyzed passwords will be displayed.

## LEVELs and PARAMs
The security level specifies that passwords must comply with all rules at that and lower levels.
* LEVEL 1: The password contains at least 1 uppercase and 1 lowercase letter.
* LEVEL 2: The password contains characters from at least PARAM groups.

    #### Groups: ####
     
             lowercase letters (a-z)
             uppercase letters (A-Z)
             numbers (0-9)
             special characters (Ascii 32-126)
                
* LEVEL 3: The password does not contain the same sequence of characters of at least PARAM.
* LEVEL 4: The password does not contain two identical substrings of at least PARAM.

## Statistics include:
- number of different characters found in all passwords
- length of the shortest password	
- average password length

Statistics include all passwords.

## Details
The password is entered on a separate line.
Contains only Unique characters, except newline character.
The maximum length of the password is 100 characters, otherwise it is invalid data.
The program supports an unlimited number of passwords.
