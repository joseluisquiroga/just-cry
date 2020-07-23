

/*************************************************************

secure_gets.h
(C 2007) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

A 'gets' function that does not echo.

--------------------------------------------------------------*/


#ifndef SECURE_GETS_H
#define SECURE_GETS_H

#include "tools.h"

#ifdef WIN32
#define DEL_KEY 8
#include "conio.h"
inline
void secure_gets(secure_row<char>& s_rr){
	char ky = 0;
	while(ky != '\r'){
		ky = getch();
		if(ky == DEL_KEY){
			if(! s_rr.is_empty()){
				s_rr.pop();
			}
		} else 
		if(ky != '\r'){
			s_rr.push((char)ky);
		}
	}
}
#endif

#ifdef __linux
#include "termios.h"
#define DEL_KEY 127
inline
void secure_gets(secure_row<char>& s_rr){
	char ky = 'X'; 
	struct termios original_t, new_t; 

	tcgetattr(fileno(stdin), &original_t); 
	new_t = original_t; 

	new_t.c_lflag &= ~(ICANON | ECHO); 
	tcsetattr(fileno(stdin), TCSAFLUSH, &new_t); 
	fflush(stdin); 

	while(ky != '\n'){
		ky = getchar();
		if(ky == DEL_KEY){
			if(! s_rr.is_empty()){
				s_rr.pop();
			}
		} else 
		if(ky != '\n'){
			s_rr.push((char)ky);
		}
	}

	tcsetattr(fileno(stdin), TCSANOW, &original_t); 
}
#endif

#endif // SECURE_GETS_H


