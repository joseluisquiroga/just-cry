

/*************************************************************

platform.h
(C 2025) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

Some macros that allow to indent better platform 
dependant code.

Insted of

#ifdef MY_PLATFORM
						<some_code>
#endif

that can be messy when code has several platforms 
dependant code. Specially inside functions.

Write:
		
					MY_PLAT_COD(
						<some_code>
					);

to make the code more clear.

--------------------------------------------------------------*/


#ifndef PLATFORM_H
#define PLATFORM_H

#define MARK_USED(X)  ((void)(&(X)))

#ifdef WIN32
#define WIN32_COD(prm)	prm
#else
#define WIN32_COD(prm)	/**/
#endif


#ifdef __linux
#define LINUX_COD(prm)	prm
#else
#define LINUX_COD(prm)	/**/
#endif


#endif // PLATFORM_H


