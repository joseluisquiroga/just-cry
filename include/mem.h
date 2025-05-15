

/*************************************************************

mem.h  
(C 2025) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

Mem managment.

--------------------------------------------------------------*/


#ifndef JLQ_MEM_H
#define JLQ_MEM_H

#include <cassert>
#include <cstdlib>
#include <cstring>
#include "platform.h"

#define NULL_PT		NULL

#ifdef FULL_DEBUG
#define DBG(prm) prm
#else
#define DBG(prm) /**/ \

// end_of_def
#endif

#define DBG_CK(prm)	   	DBG(assert(prm))
//define DBG_THROW(prm) 	DBG_CK(prm)
#define DBG_THROW(prm) 		;
#define DBG_THROW_CK(prm) 	DBG_THROW(assert(prm))

#ifdef NO_MEM_CTRL
#define MEM_CTRL(prm) ;
#else
#define MEM_CTRL(prm) prm
#endif

#ifdef SECURE_MEM
#define MEM_SRTY(prm) prm
#else
#define MEM_SRTY(prm) ;
#endif

#define MEM_CK(prm)		DBG_CK(prm)

typedef long			error_code_t;
typedef unsigned long	mem_size;
typedef char			t_1byte;
typedef unsigned int	t_4byte;
typedef t_4byte			t_dword;

#define MAX_UTYPE(type)		((type)(-1))

#define MAX_MEM_SZ		MAX_UTYPE(mem_size)

enum mem_exception_code { 
	k_mem_01_exception = 1,
	k_mem_02_exception,
	k_last_mem_exception
};

inline
void abort_func(long val, char* msg = NULL_PT){
	std::cerr << std::endl << "ABORTING! " << msg << std::endl; 
	std::cerr << "Type ENTER.\n";
	getchar();
	exit(val);
}

//======================================================================
// glb_mem_data

class glb_mem_data;
extern glb_mem_data MEM_STATS;

#define DEFINE_MEM_STATS	glb_mem_data MEM_STATS

class glb_mem_data {
public:
	typedef void (*memout_func_t)();

	mem_size 		num_bytes_in_use;
	mem_size 		num_bytes_available;
	memout_func_t	set_memout_func;
	bool			use_secure_alloc;

	glb_mem_data(){
		num_bytes_in_use = 0;
		num_bytes_available = 0;
		set_memout_func = NULL_PT;
		use_secure_alloc = false;
	}

	~glb_mem_data(){
		MEM_CK(num_bytes_in_use == 0);
	}
};


//======================================================================
// 'malloc()'-style memory allocation -- never returns NULL_PT; aborts instead:

template<class obj_t> static inline obj_t* 
tpl_malloc(size_t the_size = 1){
	mem_size mem_sz = the_size * sizeof(obj_t);
	MEM_CTRL(
		MEM_CK((MAX_MEM_SZ - mem_sz) > MEM_STATS.num_bytes_in_use);
		MEM_STATS.num_bytes_in_use += mem_sz;

		if(	(MEM_STATS.num_bytes_available > 0) && 
			(MEM_STATS.num_bytes_in_use > MEM_STATS.num_bytes_available) )
		{
			if(MEM_STATS.set_memout_func != NULL_PT){
				(*MEM_STATS.set_memout_func)();
			} else {
				error_code_t err_cod = k_mem_01_exception;
				DBG_THROW_CK(k_mem_01_exception != k_mem_01_exception);
				throw err_cod;
				std::cerr << "FATAL ERROR. Memory exhausted" << std::endl;
				abort_func(0);
			}
		}
	);

	obj_t*   tmp = (obj_t*)malloc(mem_sz);
	if((tmp == NULL_PT) && (the_size != 0)){
		error_code_t err_cod = k_mem_02_exception;
		DBG_THROW_CK(k_mem_02_exception != k_mem_02_exception);
		throw err_cod;
		std::cerr << "FATAL ERROR. Memory exhausted" << std::endl;
		abort_func(0);
	}
	return tmp; 
}

template<class obj_t> static inline obj_t* 
tpl_secure_realloc(obj_t* ptr, size_t old_size, size_t the_size){
	MEM_CK(the_size > old_size);

	mem_size mem_sz = the_size * sizeof(obj_t);
	obj_t*   tmp = (obj_t*)malloc(mem_sz);
	if((tmp == NULL_PT) && (the_size != 0)){
		error_code_t err_cod = k_mem_02_exception;
		DBG_THROW_CK(k_mem_02_exception != k_mem_02_exception);
		throw err_cod;
		std::cerr << "FATAL ERROR. Memory exhausted." << std::endl;
		abort_func(0);
	}

	if(ptr != NULL_PT){
		mem_size old_mem_sz = old_size * sizeof(obj_t);
		memcpy(tmp, ptr, old_mem_sz);
		memset(ptr, 0, old_mem_sz);
		free(ptr);
	}
	return tmp; 
}

template<class obj_t> static inline obj_t* 
tpl_realloc(obj_t* ptr, size_t old_size, size_t the_size){
	mem_size mem_sz = the_size * sizeof(obj_t);
	MEM_CTRL(
		mem_size old_mem_sz = old_size * sizeof(obj_t);
		MEM_CK(MEM_STATS.num_bytes_in_use >= old_mem_sz);
		MEM_STATS.num_bytes_in_use -= old_mem_sz;
		MEM_CK((MAX_MEM_SZ - mem_sz) > MEM_STATS.num_bytes_in_use);
		MEM_STATS.num_bytes_in_use += mem_sz;

		if(	(MEM_STATS.num_bytes_available > 0) && 
			(MEM_STATS.num_bytes_in_use > MEM_STATS.num_bytes_available) )
		{
			if(MEM_STATS.set_memout_func != NULL_PT){
				(*MEM_STATS.set_memout_func)();
			} else {
				error_code_t err_cod = k_mem_01_exception;
				DBG_THROW_CK(k_mem_01_exception != k_mem_01_exception);
				throw err_cod;
				std::cerr << "FATAL ERROR. Memory exhausted." << std::endl;
				abort_func(0);
			}
		}
	);
	MEM_SRTY(
		if(MEM_STATS.use_secure_alloc){
			return tpl_secure_realloc(ptr, old_size, the_size); 
		}
	);
	obj_t*   tmp = (obj_t*)realloc((void*)ptr, mem_sz);
	if((tmp == NULL_PT) && (the_size != 0)){
		error_code_t err_cod = k_mem_02_exception;
		DBG_THROW_CK(k_mem_02_exception != k_mem_02_exception);
		throw err_cod;
		std::cerr << "FATAL ERROR. Memory exhausted." << std::endl;
		abort_func(0);
	}
	return tmp; 
}

template<class obj_t> static inline void 
tpl_free(obj_t*& ptr, size_t the_size = 1){
	if(ptr != NULL_PT){ 
		MEM_SRTY(
			mem_size s_old_mem_sz = the_size * sizeof(obj_t);
			if(MEM_STATS.use_secure_alloc){
				memset(ptr, 0, s_old_mem_sz);
			}
		);
		free(ptr); 
		ptr = NULL_PT;
	}
	MEM_CTRL(
		mem_size old_mem_sz = the_size * sizeof(obj_t);
		MEM_CK(MEM_STATS.num_bytes_in_use >= old_mem_sz);
		MEM_STATS.num_bytes_in_use -= old_mem_sz;
	);
}




#endif // JLQ_MEM_H


