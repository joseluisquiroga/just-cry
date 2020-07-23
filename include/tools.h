

/*************************************************************

tools.h  
(C 2007) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

Base classes and abstract data types to code the system.

last update: 29 Ago 2007.

--------------------------------------------------------------*/


#ifndef TOOLS_H
#define TOOLS_H

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <new>

#include "platform.h"
#include "mem.h"

#ifndef BIT_ROW_H
#define k_first_tools_exception k_last_mem_exception
#else
#define k_first_tools_exception k_last_bit_row_exception
#endif

enum tool_exception_code { 
	k_tools_01_exception = k_first_tools_exception,
	k_tools_02_exception,
	k_tools_03_exception,
	k_tools_04_exception,
	k_tools_05_exception,
	k_tools_06_exception,
	k_tools_07_exception,
	k_tools_08_exception,
	k_tools_09_exception,
	k_tools_10_exception,
	k_tools_11_exception,
	k_last_tool_exception
};

#define NUM_BYTES_IN_KBYTE	1024

// 'integer' must be of a signed type
typedef long			integer;
typedef integer			row_index;
typedef char			comparison;

#define CMP_FN_T(nm_fun) comparison (*nm_fun)(obj_t const & obj1, obj_t const & obj2)

#define	as_bool(prm)	((prm) != 0)

enum	cmp_is_sub {
	k_lft_is_sub = -1,
	k_no_is_sub = 0,
	k_rgt_is_sub = 1
};

// size_t

#ifndef k_num_bits_byte
#define k_num_bits_byte		8
#endif

#define TOOLS_CK(prm)		DBG_CK(prm)

#define MIN_TYPE(type)		(((type)1) << (sizeof(type) * k_num_bits_byte - 1))
#define MAX_TYPE(type)		(- (MIN_TYPE(type) + 1))

#define MIN_INTEGER		MIN_TYPE(integer)
#define MAX_INTEGER		MAX_TYPE(integer)

#define MIN_INDEX		MIN_TYPE(row_index)
#define MAX_INDEX		MAX_TYPE(row_index)

#define SUB_SET_OPS		4		// each loop counts as this num ops

#define indent_fmt		"%-*d"	

#define SELEC_SORT_LIM  	10

#ifndef INVALID_IDX
#define INVALID_IDX		-1
#endif

#ifndef FILL_FULL_CAP
#define FILL_FULL_CAP	-100
#endif

#ifndef START_CAP
#define START_CAP 		16	// avoid mem problems (due to malloc, realloc failures)
#endif

#define SZ_ATTRIB_T(the_type)	row_data<the_type>::sz
#define CAP_ATTRIB_T(the_type)	row_data<the_type>::cap

#define SZ_ATTRIB		row_data<obj_t>::sz
#define CAP_ATTRIB		row_data<obj_t>::cap

template <bool> struct ILLEGAL_USE_OF_OBJECT;
template <> struct ILLEGAL_USE_OF_OBJECT<true>{};
#define OBJECT_COPY_ERROR ILLEGAL_USE_OF_OBJECT<false>()

//======================================================================
// number funcs

inline 
long
log2(long val){
	long ln_v = 0;
	while(val > 1){
		ln_v++;
		val >>= 1;
	}
	return ln_v;
}

inline 
comparison 
cmp_long(long const & n1, long const & n2){ 
	if(n1 == n2){ return 0; }
	if(n1 < n2){ return -1; }
	return 1;
}

inline 
comparison 
cmp_integer(integer const & i1, integer const & i2){ 
	if(i1 == i2){ return 0; }
	if(i1 < i2){ return -1; }
	return 1;
}

//======================================================================
// Base types and funcs

typedef char	trinary;

template<class obj_t> static inline obj_t min(obj_t x, obj_t y) { return (x < y) ? x : y; }
template<class obj_t> static inline obj_t max(obj_t x, obj_t y) { return (x > y) ? x : y; }

WIN32_COD(
inline
std::ostream& operator<<(std::ostream& os, __int64 ii ){
	char buf[30];
	sprintf(buf,"%I64d", ii );
	os << buf;
	return os;
}
)


template<class obj_t> 
static inline row_index
get_idx_of_pt(obj_t* data, obj_t* pt_obj, row_index the_size){
	row_index pt_idx = INVALID_IDX;
	if(data != NULL_PT){
		long pt1 = (long)data;
		long pt2 = pt1 + (sizeof(obj_t) * the_size);
		long pt3 = (long)pt_obj;
		bool in_range = (pt1 <= pt3) && (pt3 < pt2);
		bool in_place = (((pt3 - pt1) % sizeof(obj_t)) == 0);
		if(in_range && in_place){
			pt_idx = ((pt3 - pt1) / sizeof(obj_t));
		}
	}
	return pt_idx;
}

//======================================================================
// Time:


#ifdef WIN32
#include <ctime>
static inline double cpu_time(void){
	// This is a slow function use with care in performance code
	clock_t ct = clock();
	if(ct == -1){ return (double)ct; }
	return (((double)ct) / CLOCKS_PER_SEC);
}
#endif

#ifdef __linux
#include <sys/time.h>
#include <sys/resource.h>
static inline double cpu_time(void){
	// This is a slow function use with care in performance code
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	return (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1000000; 
}
#endif

//======================================================================
// flags

#define	k_flag0		((char)0x01)
#define	k_flag1		((char)0x02)
#define	k_flag2		((char)0x04)
#define	k_flag3		((char)0x08)
#define	k_flag4		((char)0x10)
#define	k_flag5		((char)0x20)
#define	k_flag6		((char)0x40)
#define	k_flag7		((char)0x80)

static inline
char	set_flag(char& flags, char bit_flag){
	flags = (char)(flags | bit_flag);
	return flags;
}

static inline 
char 	reset_flag(char& flags, char bit_flag){
	flags = (char)(flags & ~bit_flag);
	return flags;
}

static inline 
bool	get_flag(char flags, char bit_flag){
	char  resp  = (char)(flags & bit_flag);
	return (resp != 0);
}


//======================================================================
// yield:

#ifdef WIN32
#include <windows.h>
static inline void yield(void){
	Sleep(0);
}
#endif

#ifdef __linux
#include <sched.h>
static inline void yield(void){
	sched_yield();
}
#endif


//======================================================================
// random


static inline
long 
init_random_nums(long seed = 0){
	if(seed == 0){
		seed = time(0);
	}
	srand(seed);
	return seed;
}

static inline
long
gen_random_num(long min, long max){
	// min is inclusive
	// max is exclusive

	long diff = 0, resp = 0;
	diff = max - min;
	if(diff == 0){ 
		return min; 
	}
	if(diff < 0){ diff = -diff; }
	resp = min + (rand() % diff);
	return resp;
}


//======================================================================
// row_data


// NOTE. ONLY for types that can be used with 'realloc'


template<class obj_t>
class row_data {
protected:
	row_index sz;
	row_index cap;

public:
	typedef comparison (*cmp_func_t)(obj_t const & obj1, obj_t const & obj2);

	row_index	get_cap(){
		return cap;
	}

	virtual bool	ck_valid_pt(obj_t* pt_obj){ 
		MARK_USED(pt_obj);
		error_code_t err_cod = k_tools_06_exception;
		DBG_THROW_CK(k_tools_06_exception != k_tools_06_exception);
		throw err_cod;
		std::cerr << "func: 'row_data::ck_valid_pt'" << std::endl;
		abort_func(0); 
	}

	virtual void	set_cap(row_index min_cap){ 
		MARK_USED(min_cap);
		error_code_t err_cod = k_tools_03_exception;
		DBG_THROW_CK(k_tools_03_exception != k_tools_03_exception);
		throw err_cod;
		std::cerr << "func: 'row_data::set_cap'" << std::endl;
		abort_func(0); 
	}

	virtual void	clear(bool destroy = false, bool dealloc = false, row_index from = 0){ 
		MARK_USED(destroy);
		MARK_USED(dealloc);
		MARK_USED(from);
		error_code_t err_cod = k_tools_04_exception;
		DBG_THROW_CK(k_tools_04_exception != k_tools_04_exception);
		throw err_cod;
		std::cerr << "func: 'row_data::clear'" << std::endl;
		abort_func(0); 
	}

	virtual obj_t&		pos(row_index idx){ 
		MARK_USED(idx);
		error_code_t err_cod = k_tools_05_exception;
		DBG_THROW_CK(k_tools_05_exception != k_tools_05_exception);
		throw err_cod;
		std::cerr << "func: 'row_data::pos'" << std::endl;
		abort_func(0); 
		return *((obj_t*)NULL_PT);
	}

	row_index	sz_in_bytes(){
		return (sz * sizeof(obj_t));
	}

	bool	is_empty(){
		return (sz == 0);
	}

	// constructors
	row_data(): sz(0), cap(0) {}

	/*virtual	~row_data(){
		std::cerr << "func: 'row_data::~row_data'" << std::endl;
		abort_func(0); 
	}*/

	// Size operations:
	void	grow(row_index min_cap){
		if(min_cap <= cap){ return; }
		row_index nxt_cap = cap;

		if(nxt_cap == 0){ 
			nxt_cap = START_CAP; 
		}

		do{ 
			nxt_cap = nxt_cap * 2; 
		} while(nxt_cap < min_cap);

		TOOLS_CK(nxt_cap > 1);
		set_cap(nxt_cap);
	}

	//virtual	if kk_queue
	row_index	size() const { 
		return sz; 
	}

	row_index	last_idx(){
		return (size() - 1);
	}

	//virtual	if kk_queue
	bool		is_full() { 
		return (sz == cap); 
	}

	// Stack interface:
	void	push(const obj_t elem){ 
		if(is_full()){ 
			grow(sz + 2); 
		}
		new (&pos(sz)) obj_t(elem); 
		sz++; 
	}

	obj_t&	inc_sz(){ 
		if(is_full()){ 
			grow(sz + 2);
		}
		new (&pos(sz)) obj_t();
		sz++; 
		return last();
	}

	void	minc_sz(long num_incs){
		for(long aa = 0; aa < num_incs; aa++){
			inc_sz();
		}
	}

	void	dec_sz(){ 
		sz--; 
		pos(sz).~obj_t(); 
	}

	obj_t		pop(){ 
		TOOLS_CK(sz > 0);
		sz--; 
		obj_t tmp1 = pos(sz);
		pos(sz).~obj_t();
		return tmp1; 
	}

	obj_t&		first(){ 
		TOOLS_CK(sz > 0);
		return pos(0); 
	}

	obj_t&		last(){ 
		TOOLS_CK(sz > 0);
		return pos(sz - 1); 
	}

	void	swap(row_index idx1, row_index idx2){ 
		obj_t tmp1 = pos(idx1);
		pos(idx1) = pos(idx2);
		pos(idx2) = tmp1;
	}

	row_index	
	random_swap_last(){
		TOOLS_CK(sz > 0);
		row_index idx1 = sz - 1;
		row_index idx2 = gen_random_num(0, sz);
		if(idx1 != idx2){
			swap(idx1, idx2);
		}
		return idx2;
	}

	obj_t	swap_pop(row_index idx){
		obj_t tmp1 = pos(idx);
		sz--;
		pos(idx) = pos(sz);
		pos(sz).~obj_t();
		return tmp1;
	}

	void	swapop(row_index idx){ 
		sz--;
		pos(idx) = pos(sz);
		pos(sz).~obj_t();
	}

	// Vector interface:

	void	fill(const obj_t elem, row_index num_fill = INVALID_IDX,
					row_index from_idx = 0)
	{ 
		if(from_idx == INVALID_IDX){
			from_idx = sz;
		} 

		if(num_fill == INVALID_IDX){
			num_fill = sz;
		} else 
		if(num_fill == FILL_FULL_CAP){
			num_fill = cap;
		} else {
			num_fill += from_idx;
		}
		set_cap(num_fill);
		row_index ii = from_idx;
		for(ii = from_idx; ((ii < sz) && (ii < num_fill)); ii++){
			pos(ii) = elem;
		}
		for(; ii < num_fill; ii++){
			push(elem);
		}
	}

	void	fill_new(row_index num_fill = INVALID_IDX){ 
		clear(true);
		if(num_fill == INVALID_IDX){
			num_fill = sz;
		}
		if(num_fill == FILL_FULL_CAP){
			num_fill = cap;
		}
		set_cap(num_fill);
		for(row_index ii = 0; ii < num_fill; ii++){
			inc_sz();
		}
	}

	bool	is_valid_idx(row_index idx){
		return ((idx >= 0) && (idx < sz));
	}

	obj_t&       operator [] (row_index idx)        { 
		TOOLS_CK(is_valid_idx(idx));
		return pos(idx); 
	}

	// Don't allow copying (error prone):
	// force use of referenced rows

	row_data<obj_t>&  operator = (row_data<obj_t>& other) { 
		OBJECT_COPY_ERROR; 
	}

	row_data(row_data<obj_t>& other){ 
		OBJECT_COPY_ERROR; 
	}

    // Duplication (preferred instead):
    void copy_to(row_data<obj_t>& r_cpy, row_index first_ii = 0, row_index last_ii = -1){ 
		r_cpy.clear(true, false); 
		append_to(r_cpy, first_ii, last_ii);
	}

    void append_to(row_data<obj_t>& dest, 
				row_index first_ii = 0, row_index last_ii = -1,
				bool inv = false)
	{ 
		if((last_ii < 0) || (last_ii > sz)){
			last_ii = sz;
		}
		if((first_ii < 0) || (first_ii > last_ii)){
			first_ii = 0;
		}
		dest.set_cap(dest.sz + (last_ii - first_ii)); 
		row_index ii = INVALID_IDX;
		if(inv){
			for(ii = last_ii - 1; ii >= first_ii; ii--){
				obj_t ob = pos(ii);
				dest.push(ob);
			}
		} else {
			for(ii = first_ii; ii < last_ii; ii++){
				obj_t ob = pos(ii);
				dest.push(ob);
			}
		}
	}

	// io funcs

	std::ostream&	print_row_data(
		std::ostream& os, 
		bool with_lims = true,
		const char* sep = " ", 
		row_index low = INVALID_IDX, 
		row_index hi = INVALID_IDX,
		bool pointers = false,
		row_index grp_sz = -1,
		const char* grp_sep = "\n"
		)
	{
		row_index num_elem = 1;
		if(with_lims){ os << "["; }
		for(row_index ii = 0; ii < sz; ii++){
			if(ii == low){ os << ">"; }
			if(!pointers){
				os << pos(ii);
			} else {
				os << &(pos(ii));
			}
			if(ii == hi){ os << "<"; }
			os << sep;
			if((grp_sz > 1) && ((num_elem % grp_sz) == 0)){
				os << grp_sep;
			}
			num_elem++;
		}
		if(with_lims){ os << "] "; }
		os.flush();
		return os;
	}

	// sort & selec funcs

	void	selec_sort(cmp_func_t cmp_fn){
		row_index	ii, jj, best_ii;
		obj_t	tmp;
		for (ii = 0; ii < (sz - 1); ii++){
			best_ii = ii;
			for (jj = ii+1; jj < sz; jj++){
				if((*cmp_fn)(pos(jj), pos(best_ii)) < 0){
					best_ii = jj;
				}
			}
			tmp = pos(ii); 
			pos(ii) = pos(best_ii); 
			pos(best_ii) = tmp;
		}
	}

	bool	is_sorted(cmp_func_t cmp_fn){
		if(sz == 0){ return true; }
		obj_t	lst = pos(0);
		for(row_index ii = 1; ii < sz; ii++){
			if((*cmp_fn)(lst, pos(ii)) > 0){
				return false;
			}
			lst = pos(ii);
		}
		return true;
	}

	bool	equal_to(row_data<obj_t>& rw2, row_index first_ii = 0, row_index last_ii = -1){
		if((last_ii < 0) && (sz != rw2.size())){
			return false;
		}
		if((last_ii < 0) || (last_ii > sz)){
			last_ii = sz;
		}
		if((first_ii < 0) || (first_ii > last_ii)){
			first_ii = 0;
		}

		if(! is_valid_idx(first_ii)){ return false; }
		if(! is_valid_idx(last_ii - 1)){ return false; }
		if(! rw2.is_valid_idx(first_ii)){ return false; }
		if(! rw2.is_valid_idx(last_ii - 1)){ return false; }

		//for(row_index ii = 0; ii < sz; ii++){
		for (row_index ii = first_ii; ii < last_ii; ii++){
			if(pos(ii) != rw2.pos(ii)){
				return false;
			}
		}
		return true;
	}
};

template<class obj_t>
inline
std::ostream&	operator << (std::ostream& os, row_data<obj_t>& rr){
	rr.print_row_data(os, true, " ");
	return os;
}

template<class obj_t>
inline
row_data<obj_t>&	operator << (row_data<obj_t>& rr, const obj_t elem){
	rr.push(elem);
	return rr;
}

/*
inline
row_data<obj_t>&	operator >> (row_data<obj_t>& rr, obj_t& elem){
	elem = rr.pop();
	return rr;
}*/

//================================================================
// row_iter

template<class obj_t>
class row_iter {
public:
	row_data<obj_t>& 	the_row;
	row_index			the_ref;

	row_iter(row_data<obj_t>& d_row) : the_row(d_row){
		the_ref = INVALID_IDX;
	}
	row_iter(row_iter& row_it): the_row(row_it.the_row){
		the_ref = INVALID_IDX;
	}
	~row_iter(){
	}

	long	size(){
		return the_row.size();
	}

	void	go_first_ref(){
		if(size() > 0){
			the_ref = 0;
		} else {
			the_ref = INVALID_IDX;
		}
	}

	void	go_last_ref(){
		if(size() > 0){
			the_ref = the_row.last_idx();
		} else {
			the_ref = INVALID_IDX;
		}
	}

	obj_t&	get_obj(){
		return the_row[the_ref]; 
	}
	
	bool 	in_null(){
		return ((the_ref < 0) || (the_ref >= size()));
	}

	void	go_next(){
		the_ref++;
	}

	void	go_prev(){
		the_ref--;
	}

	void 	operator ++ (){
		go_next();
	}

	void 	operator -- (){
		go_prev();
	}

	void 	operator ++ (int) { ++(*this); }

	void 	operator -- (int) { --(*this); }
};

//======================================================================
// row

#define DATA_ATTRIB_T(the_type)	row<the_type>::data

#define DATA_ATTRIB	row<obj_t>::data

template<class obj_t>
class row: public row_data<obj_t> {
protected:
	obj_t*  data;

public:
	typedef comparison (*cmp_func_t)(obj_t const & obj1, obj_t const & obj2);

	const t_1byte*	get_data(){
		return ((t_1byte*)data);
	}

	long			get_data_sz(){
		return (SZ_ATTRIB * sizeof(obj_t));
	}
	
	const obj_t*	get_c_array(){
		return data;
	}

	long			get_c_array_sz(){
		return SZ_ATTRIB;
	}

	void	init_s_bit_row(s_bit_row& rr){
		rr.init_data(((t_1byte*)data), get_data_sz());
	}
	
	virtual bool	ck_valid_pt(obj_t* pt_obj){ 
		row_index pt_idx = get_idx_of_pt<obj_t>(data, pt_obj, SZ_ATTRIB);
		return (pt_idx != INVALID_IDX);
	}

	virtual void	set_cap(row_index min_cap){ 
		if(min_cap <= CAP_ATTRIB){ return; }
		row_index old_cap = CAP_ATTRIB;
		TOOLS_CK(old_cap >= 0);
		//CAP_ATTRIB = min_cap + CAP_MARGIN;
		CAP_ATTRIB = min_cap;
		obj_t* n_dat = tpl_realloc(data, old_cap, CAP_ATTRIB);
		data = n_dat;
	}

	virtual
	void	set_size(row_index n_sz){ 
		set_cap(n_sz);
		SZ_ATTRIB = n_sz;
	}

	virtual void	clear(bool destroy = false, bool dealloc = false, row_index from = 0){ 
		if(data != NULL_PT){
			if(from != 0){
				dealloc = false;
			}
			if(destroy){ 
				for(row_index ii = from; ii < SZ_ATTRIB; ii++){ 
					pos(ii).~obj_t();
				}
			}
			SZ_ATTRIB = from;
			if(dealloc){ 
				tpl_free(data, CAP_ATTRIB);
				data = NULL_PT;
				CAP_ATTRIB = 0; 
			}
		} 
	}

	virtual 
	obj_t&		pos(row_index idx){ 
		return data[idx];
	}

    virtual
	void move_to(row<obj_t>& dest, bool just_init = false){ 
		if(!just_init){ 
			dest.clear(true, true); 
		}
		dest.data = data; 
		dest.sz = SZ_ATTRIB; 
		dest.cap = CAP_ATTRIB; 
		data = NULL_PT; 
		SZ_ATTRIB = 0; 
		CAP_ATTRIB = 0; 
	}

	void mem_copy_to(row<obj_t>& r_cpy){ 
		r_cpy.set_cap(SZ_ATTRIB);
		memcpy(r_cpy.data, data, row_data<obj_t>::sz_in_bytes());
		r_cpy.sz = SZ_ATTRIB;
	}

	// constructors
	row(row_index pm_cap = 0): row_data<obj_t>(), data(NULL_PT){ 
		if(pm_cap > 0){ row<obj_t>::set_cap(pm_cap); }
	}

	~row(){
		clear(true, true);
	}

	void	mix_sort(cmp_func_t cmp_fn);

	// adhere asummes:
	//		- 'shared' of 'this' with 'set' is empty (no intersec)
	//		- 'this' & 'set' are sorted by cmp_fn (min to max)
	//		- each elem in 'this' & 'set' is unique
	void	sorted_set_adhere(row<obj_t>& set, cmp_func_t cmp_fn);

	// reduce asummes:
	//		- 'set' is subset of 'this' (intersec is set)
	//		- 'this' & 'set' are sorted by cmp_fn (min to max)
	//		- each elem in 'this' & 'set' is unique
	void	sorted_set_reduce(row<obj_t>& set, cmp_func_t cmp_fn);

	// shared assummes: 
	//		- 'this' & 'set' are sorted by cmp_fn (min to max)
	//		- each elem in 'this' & 'set' is unique
	//		- 'shared' output is NOT sorted
	void	sorted_set_shared(row<obj_t>& shared, 
				row<obj_t>& set, cmp_func_t cmp_fn);

	cmp_is_sub		sorted_set_is_subset(row<obj_t>& set, 
						cmp_func_t cmp_fn, bool& are_eq);

	long	shuffle(row_index from = 0, bool init_random = true);

};

template<class obj_t>
inline
comparison		cmp_with(row<obj_t>& set1, row<obj_t>& set2, CMP_FN_T(cmp_fn)){
	//row<obj_t> const& set1 = *this;
	if(set1.size() < set2.size()){
		return -1;
	}
	if(set1.size() > set2.size()){
		return 1;
	}
	TOOLS_CK(set1.size() == set2.size());
	for(row_index ii = 0; ii < set1.size(); ii++){
		comparison cmp_resp = (*cmp_fn)(set1.pos(ii), set2.pos(ii));
		if(cmp_resp != 0){ 
			return cmp_resp; 
		}
	}
	return 0;
}

//======================================================================
// secure_row

template<class obj_t>
class secure_row: public row<obj_t> {
	public:
	virtual void	set_cap(row_index min_cap){ 
		MEM_SRTY(
			bool old_sec = MEM_STATS.use_secure_alloc;
			MEM_STATS.use_secure_alloc = true
		);
		row<obj_t>::set_cap(min_cap);
		MEM_SRTY(MEM_STATS.use_secure_alloc = old_sec);
	}
	virtual void	clear(bool destroy = false, bool dealloc = false, row_index from = 0){ 
		MEM_SRTY(
			bool old_sec = MEM_STATS.use_secure_alloc;
			MEM_STATS.use_secure_alloc = true
		);
		row<obj_t>::clear(destroy, dealloc, from);
		MEM_SRTY(MEM_STATS.use_secure_alloc = old_sec);
	}
};

//======================================================================
// s_row

// careful: cannot free the given data while using the 
// s_row object because it is a pointer to the given data. 

template<class obj_t>
class s_row : public row<obj_t> {
private:
	virtual
	void	grow(row_index bits_cap){ MARK_USED(bits_cap); }
	virtual
	void	set_cap(row_index bits_cap){ MARK_USED(bits_cap); }
	virtual
	void	set_size(row_index bits_sz){ MARK_USED(bits_sz); }
	virtual
	void	push(const bool elem){ MARK_USED(elem); }
	virtual
	void	inc_sz(){}
	virtual
	void	dec_sz(){}
	virtual
	bool	pop(){ return false; }
	virtual
	bool	swap_pop(row_index idx){ MARK_USED(idx); return false; }
	virtual
	void	swapop(row_index idx){ MARK_USED(idx); }

public:
	s_row(t_1byte* dat = NULL_PT, long dat_num_bytes = 0){
		init_data(dat, dat_num_bytes);
	}

	~s_row(){
		clear();
	}

	virtual
	void	clear(bool reset_them = false, bool dealloc = false, row_index from = 0){
		MARK_USED(reset_them);
		MARK_USED(dealloc);
		MARK_USED(from);
		SZ_ATTRIB = 0;
		CAP_ATTRIB = 0;
		DATA_ATTRIB = NULL_PT;
	} 

	long to_objs(long num_bytes){
		return (num_bytes / sizeof(obj_t));
	}

	void init_data(t_1byte* dat, long dat_num_bytes){
		SZ_ATTRIB = to_objs(dat_num_bytes);
		CAP_ATTRIB = to_objs(dat_num_bytes);
		if(CAP_ATTRIB > 0){
			DATA_ATTRIB = (obj_t*)dat;
		} else {
			DATA_ATTRIB = NULL_PT;
		}
	}

	void init_data_with_s_bit_row(s_bit_row& rr){
		SZ_ATTRIB = to_objs(rr.get_bytes_cap());
		CAP_ATTRIB = to_objs(rr.get_bytes_cap());
		if(CAP_ATTRIB > 0){
			DATA_ATTRIB = (obj_t*)(rr.data);
		} else {
			DATA_ATTRIB = NULL_PT;
		}
	}

	void erase_data(){
		if(DATA_ATTRIB == NULL_PT){
			return;
		}
		memset(DATA_ATTRIB, 0, (SZ_ATTRIB * sizeof(obj_t)));
	}
};

//======================================================================
// picker

template <class obj_t>
class picker {
public:
	bool			stopped;
	row<obj_t>&		picker_row;
    row_index		pick_idx;

	picker(row<obj_t>& the_row) : picker_row(the_row), pick_idx(0) {
		stopped = false;
	}

	~picker(){
	}

    obj_t   pick() { 
		row_index sz = picker_row.size();
		if((pick_idx >= 0) && (pick_idx < sz)){
			return picker_row[pick_idx++];
		} else {
			obj_t an_obj;
			new (&an_obj) obj_t();
			return an_obj;
		}
	}

	bool	is_picked(row_index idx){
		return ((idx >= 0) && (idx < pick_idx));
	}

	row_index	pending_size() const { 
		return picker_row.size() - pick_idx; 
	}

	void	to_pos(row_index n_idx){ 
		if(	(n_idx >= 0) && 
			(n_idx < picker_row.size())	)
		{ 
			stopped = false; 
		}
		pick_idx = n_idx;
	}

	void	stop(){
		stopped = true;
	}

	void	restart(){
		if(pick_idx > picker_row.size()){
			pick_idx = picker_row.size();
		}
		stopped = false;
	}

	bool	is_stopped(){
		return stopped;
	}

	void	to_first(){ 
		stopped = false;
		pick_idx = 0;
	}

	void	to_last(){ 
		stopped = true;
		pick_idx = picker_row.size();
	}

	bool	has_pending(){ 
		return (! stopped && (pending_size() > 0));
	}

};

//======================================================================
// k_row

template<class obj_t>
class k_row : public row_data<obj_t> {
protected:
	obj_t**		pt_data;
	row_index	first_exp;
	row_index	first_cap;
public:
	row_index		cap2i(row_index& nxt_cap, row_index& rest){
		if(first_exp == 0){
			rest = 0;
			row_index cc = 1;
			while(cc < nxt_cap){ cc <<= 1; first_exp++; }
			if(first_exp != 0){ 
				nxt_cap = cc; 
				first_cap = i2c(0);
				TOOLS_CK(first_cap == cc);
				return 0;
			}
			return -1;
		}
		TOOLS_CK(first_cap > 0);
		row_index ii = 0;
		row_index cc = first_cap;
		row_index n_cap = first_cap;
		rest = 0;
		while(n_cap < nxt_cap){
			cc <<= 1;
			n_cap += cc;
			ii++;
		}
		rest = nxt_cap - (n_cap - cc);
		//nxt_cap = n_cap; 
		return ii;
	}

	row_index		i2e(row_index ii){
		return (ii + first_exp);
	}

	row_index		i2c(row_index ii){
		row_index ee = i2e(ii);
		return (1 << ee);
	}

	virtual void	set_cap(row_index nxt_cap){ 
		if(nxt_cap <= CAP_ATTRIB){ return; }
		if(nxt_cap <= START_CAP){ nxt_cap = START_CAP; }

		row_index rest = INVALID_IDX;
		row_index old_cap = CAP_ATTRIB;
		row_index old_i = cap2i(old_cap, rest);
		row_index old_dt_sz = old_i + 1;
		TOOLS_CK(old_cap == CAP_ATTRIB);

		row_index new_i = cap2i(nxt_cap, rest);
		row_index new_dt_sz = new_i + 1;

		CAP_ATTRIB = nxt_cap;
		TOOLS_CK(first_cap == i2c(0));

		obj_t**	n_pt_dat = tpl_realloc(pt_data, old_dt_sz, new_dt_sz);
		pt_data = n_pt_dat;

		for(row_index ii = old_dt_sz; ii < new_dt_sz; ii++){
			pt_data[ii] = NULL_PT;
			pt_data[ii] = tpl_malloc<obj_t>(i2c(ii));
		}
	}

	virtual void	clear(bool destroy = false, bool dealloc = false, row_index from = 0){ 
		if(pt_data != NULL_PT){
			if(from != 0){
				dealloc = false;
			}
			if(destroy){ 
				for(row_index ii = from; ii < SZ_ATTRIB; ii++){ 
					pos(ii).~obj_t();
				}
			}
			SZ_ATTRIB = from;
			if(dealloc){ 
				TOOLS_CK(first_exp > 0);
				row_index rest = INVALID_IDX;
				row_index dt_sz = cap2i(CAP_ATTRIB, rest) + 1;
				for(row_index jj = 0; jj < dt_sz; jj++){
					//if(pt_data[jj] != NULL_PT)
					tpl_free(pt_data[jj], i2c(jj));
					pt_data[jj] = NULL_PT;
				}
				tpl_free(pt_data, dt_sz);
				pt_data = NULL_PT;
				CAP_ATTRIB = 0; 
				first_exp = 0;
				first_cap = 0;
			}
		} 
	}

	void	get_coordinates(row_index idx, 
		row_index& coor1, row_index& coor2)
	{
		if(idx < first_cap){
			coor1 = 0;
			coor2 = idx;
			return;
		}

		row_index sub_ii = INVALID_IDX;
		row_index ii = idx + 1;
		row_index dt_ii = cap2i(ii, sub_ii);

		coor1 = dt_ii;
		coor2 = sub_ii - 1;
	}

	virtual obj_t&		pos(row_index idx){ 
		row_index coor1 = INVALID_IDX;
		row_index coor2 = INVALID_IDX;
		get_coordinates(idx, coor1, coor2);
		TOOLS_CK(coor1 != INVALID_IDX);
		TOOLS_CK(coor2 != INVALID_IDX);
		return pt_data[coor1][coor2];
	}

	virtual bool	ck_valid_pt(obj_t* pt_obj){ 
		bool ck_valid = false;
		if(pt_data != NULL_PT){
			TOOLS_CK(first_exp > 0);
			row_index rest = INVALID_IDX;
			row_index dt_sz = cap2i(CAP_ATTRIB, rest) + 1;
			for(row_index jj = 0; jj < dt_sz; jj++){
				TOOLS_CK(pt_data[jj] != NULL_PT);
				row_index pt_idx = get_idx_of_pt<obj_t>(pt_data[jj], 
						pt_obj, i2c(jj));
				if(pt_idx != INVALID_IDX){
					row_index coor1_last = INVALID_IDX;
					row_index coor2_last = INVALID_IDX;
					get_coordinates(SZ_ATTRIB - 1, coor1_last, coor2_last);
					if(	(jj < coor1_last) || 
						((jj == coor1_last) && (pt_idx <= coor2_last)))
					{
						TOOLS_CK(&(pt_data[jj][pt_idx]) == pt_obj);
						ck_valid = true;
					}
					break;
				}
			}
		}
		return ck_valid;
	}

	// Constructors:
	k_row(row_index pm_cap = 0):
			row_data<obj_t>(),
			pt_data(NULL_PT), 
			first_exp(0),
			first_cap(0)
	{ 
		if(pm_cap > 0){ k_row<obj_t>::set_cap(pm_cap); }
	}

	~k_row(){
		clear(true, true);
	}

};

//======================================================================
// heap

template<class obj_t>
class heap : public row<obj_t> {
	row_index	parent(row_index idx){ return ((idx+1)>>1) - 1; }
	row_index	left(row_index idx){ return ((idx+1)<<1) - 1; }
	row_index	right(row_index idx){ return ((idx+1)<<1); }

	row_index	heapify(row_index idx);

	void		update_idx(row_index idx){ 
		if(func_idx == NULL_PT){ return; }
		(*func_idx)(row<obj_t>::pos(idx)) = idx; 
	}
	void		ck_idx(row_index idx){
		if(func_idx == NULL_PT){ return; }
		TOOLS_CK(idx == (*func_idx)(row<obj_t>::pos(idx)));
	}

public:
	typedef comparison (*cmp_func_t)(obj_t const & obj1, obj_t const & obj2);
	typedef row_index&	(*func_idx_t)(obj_t&);

	cmp_func_t	cmp_func;
	func_idx_t	func_idx;

	comparison			cmp(row_index idx1, row_index idx2){
		return (*cmp_func)(row<obj_t>::pos(idx1), row<obj_t>::pos(idx2));
	}

	comparison			cmp_obj(row_index idx1, obj_t& obj){
		return (*cmp_func)(row<obj_t>::pos(idx1), obj);
	}

	heap(cmp_func_t	f_key, func_idx_t f_idx = NULL_PT, row_index pm_cap = 0)
		: row<obj_t>(pm_cap)
	{ 
		cmp_func = f_key;
		func_idx = f_idx;
	}
	
	heap(row<obj_t>& arr, cmp_func_t f_key, func_idx_t f_idx = NULL_PT)
	{ 
		cmp_func = f_key;
		func_idx = f_idx;

		arr.move_to(*this, true);
		build();
	}

	~heap(){
		row<obj_t>::clear(true, true);
	}

	void		build();
	row_index		insert(obj_t obj);
	row_index		changed_key(row_index idx);

	obj_t		remove(row_index idx);
	obj_t		pop_top();

	obj_t		top(){ 
		if(SZ_ATTRIB > 0){ return row<obj_t>::pos(0); }
		return obj_t();
	}
	void		n_top_to(row_index nn, row<obj_t>& top_ob){
		if(SZ_ATTRIB == 0){ return; }
		for(row_index ii = 0; 
			(	(ii < SZ_ATTRIB) && 
				(top_ob.size() < nn) && 
				(cmp(0, ii) == 0)); 
			ii++)
		{
			top_ob.push(row<obj_t>::pos(ii));
		}
	}

	bool		dbg_is_heap_ok(row_index idx = 0);

	std::ostream&	print_heap(std::ostream& os, row_index idx);

	void		hsort(){
		row_index orig_sz = SZ_ATTRIB;
		for(row_index ii = orig_sz - 1; ii >= 0; ii--){
			row_data<obj_t>::swap(0, ii);
			(SZ_ATTRIB)--;
			heapify(0);
		}
		row<obj_t>::clear(true, false, orig_sz);
	}

};

template<class obj_t>
inline 
std::ostream&	operator << (std::ostream& os, heap<obj_t>& he){
	return he.print_heap(os, 0);
}

//======================================================================
// set comparison

inline
std::string	subset_cmp_str(cmp_is_sub val){
	std::string str1 = "k_invalid !!!";
	switch(val){
	case k_lft_is_sub:
		str1 = "k_lft_is_sub"; break;
	case k_no_is_sub:
		str1 = "k_no_is_sub"; break;
	case k_rgt_is_sub:
		str1 = "k_rgt_is_sub"; break;
	}
	return str1;
}

#define decl_cmp_fn(o_t, nam) comparison (*nam)(o_t const & obj1, o_t const & obj2)

template<class obj_t, class iter_t>
cmp_is_sub 
is_subset_cmp(iter_t& iter1, iter_t& iter2, 
		decl_cmp_fn(obj_t, cmp_fn), bool& are_eq)
{
	are_eq = false;

	long sz1 = iter1.size(); 
	long sz2 = iter2.size();
	bool empt1 = (sz1 == 0);
	bool empt2 = (sz2 == 0);
	if(empt1 && empt2){
		are_eq = true;
	}
	if(empt1){
		return k_lft_is_sub;
	}
	if(empt2){
		return k_rgt_is_sub;
	}

	iter_t* 	sub_iter = &iter1;
	iter_t* 	set_iter = &iter2;
	cmp_is_sub 	is_sub_val = k_lft_is_sub;

	if(sz1 > sz2){
		sub_iter = &iter2;
		set_iter = &iter1;
		is_sub_val = k_rgt_is_sub;
	}

	iter_t& hi_sub = *(sub_iter);
	iter_t 	lo_sub(hi_sub);

	iter_t& hi_set = *(set_iter);
	iter_t 	lo_set(hi_set);

	long hi_sub_to_ck = sub_iter->size() - 1; 
	long lo_sub_to_ck = 0;
 
	long hi_set_to_ck = set_iter->size() - 1;
	long lo_set_to_ck = 0;

	lo_sub.go_first_ref();
	hi_sub.go_last_ref();

	lo_set.go_first_ref();
	hi_set.go_last_ref();

	cmp_is_sub 	final_cmp = k_no_is_sub;
	bool		is_sub = false;	
	comparison 	cmp_lo = -3, cmp_hi = -3;

	TOOLS_CK((is_sub_val == k_lft_is_sub) || (is_sub_val == k_rgt_is_sub));

	while(true){
		long sub_to_ck = (hi_sub_to_ck - lo_sub_to_ck);
		long set_to_ck = (hi_set_to_ck - lo_set_to_ck);

		if(sub_to_ck < 0){
			break;
		}
		if(set_to_ck < 0){
			TOOLS_CK(final_cmp == k_no_is_sub);
			return final_cmp; 
		}

		obj_t&	lo_sub_obj = lo_sub.get_obj();
		obj_t&	hi_sub_obj = hi_sub.get_obj();
		obj_t&	lo_set_obj = lo_set.get_obj();
		obj_t&	hi_set_obj = hi_set.get_obj();

		cmp_lo = (*cmp_fn)(lo_sub_obj, lo_set_obj);
		cmp_hi = (*cmp_fn)(hi_sub_obj, hi_set_obj);

		if((sub_to_ck == 0) && ((cmp_lo == 0) || (cmp_hi == 0))){
			are_eq = (sz1 == sz2); 
			TOOLS_CK(! are_eq || (set_to_ck <= 0));
			final_cmp = is_sub_val; 
			TOOLS_CK(final_cmp != k_no_is_sub);
			return final_cmp; 
		}

		if( (sub_to_ck > set_to_ck) ||
			(cmp_lo < 0) ||
			(cmp_hi > 0) )
		{ 
			TOOLS_CK(final_cmp == k_no_is_sub);
			return final_cmp; 
		}

		if(cmp_lo > 0){ lo_set++; lo_set_to_ck++; }
		if(cmp_lo == 0){ lo_sub++; lo_set++; lo_sub_to_ck++; lo_set_to_ck++; }
		if(cmp_hi == 0){ hi_sub--; hi_set--; hi_sub_to_ck--; hi_set_to_ck--; }
		if(cmp_hi < 0){ hi_set--; hi_set_to_ck--;}
	}

	TOOLS_CK(final_cmp == k_no_is_sub);
	if((cmp_lo == 0) && (cmp_hi == 0)){
		are_eq = (sz1 == sz2); 
		//TOOLS_CK(! are_eq || ((sub_to_ck <= 0) && (set_to_ck <= 0)));
		final_cmp = is_sub_val; 
		TOOLS_CK(final_cmp != k_no_is_sub);
	} 
	return final_cmp;
}

template<class obj_t>
cmp_is_sub	
cmp_sorted_rows(row_data<obj_t>& r1, row_data<obj_t>& r2,
			decl_cmp_fn(obj_t, cmp_fn), bool& are_eq)
{
	row_iter<obj_t>	iter1(r1);
	row_iter<obj_t>	iter2(r2);

	return is_subset_cmp<obj_t, row_iter<obj_t> >(iter1, 
		iter2, cmp_fn, are_eq); 
}

//======================================================================
// FUNCTIONS

template<class obj_t>
cmp_is_sub
row<obj_t>::sorted_set_is_subset(row<obj_t>& set, 
					 cmp_func_t cmp_fn, bool& are_eq)
{
	return cmp_sorted_rows(*this, set, cmp_fn, are_eq);
}

template<class obj_t>
void	
row<obj_t>::sorted_set_shared(row<obj_t>& shared, 
			row<obj_t>& rr2, cmp_func_t cmp_fn)
{
	long lo_idx1 = 0;
	long hi_idx1 = row<obj_t>::last_idx();
	long lo_idx2 = 0;
	long hi_idx2 = rr2.last_idx();

	shared.clear();

	while(true){
		if(hi_idx1 < lo_idx1){
			break;
		}
		if(hi_idx2 < lo_idx2){
			break;
		}

		obj_t& lo_a1 = row<obj_t>::pos(lo_idx1);
		obj_t& hi_a1 = row<obj_t>::pos(hi_idx1);
		obj_t& lo_a2 = rr2[lo_idx2];
		obj_t& hi_a2 = rr2[hi_idx2];

		comparison cmp_a1 = (*cmp_fn)(lo_a1, hi_a1);
		comparison cmp_a2 = (*cmp_fn)(lo_a2, hi_a2);
		comparison cmp_hi1_lo2 = (*cmp_fn)(hi_a1, lo_a2);
		comparison cmp_hi2_lo1 = (*cmp_fn)(hi_a2, lo_a1);
		comparison cmp_lo1_lo2 = (*cmp_fn)(lo_a1, lo_a2);
		comparison cmp_hi1_hi2 = (*cmp_fn)(hi_a1, hi_a2);

		TOOLS_CK(cmp_a1 <= 0);
		TOOLS_CK(cmp_a2 <= 0);

		if(cmp_hi1_lo2 < 0){
			break;
		}
		if(cmp_hi2_lo1 < 0){
			break;
		}

		if(cmp_lo1_lo2 < 0){ lo_idx1++; }
		if(cmp_lo1_lo2 > 0){ lo_idx2++; }
		if(cmp_lo1_lo2 == 0){ 
			TOOLS_CK(lo_a1 == lo_a2);
			shared << lo_a1;
			lo_idx1++; lo_idx2++; 
		}
		if((cmp_a1 != 0) && (cmp_hi1_hi2 == 0)){ 
			TOOLS_CK(hi_a1 == hi_a2);
			shared << hi_a1;
			hi_idx1--; hi_idx2--; 
		}
		if(cmp_hi1_hi2 < 0){ hi_idx2--; }
		if(cmp_hi1_hi2 > 0){ hi_idx1--; }
	}
}

template<class obj_t>
void
row<obj_t>::sorted_set_adhere(row<obj_t>& set, cmp_func_t cmp_fn){
	if(set.is_empty()){
		return;
	}
	if(row<obj_t>::is_empty()){
		set.copy_to(*this);
		return;
	}

	DBG(bool is_sted = row<obj_t>::is_sorted(cmp_fn));
	//DBG_PRT_COND(-1, ! is_sted, os << *this);
	TOOLS_CK(is_sted);
	DBG(bool is_sted_set = set.is_sorted(cmp_fn));
	//DBG_PRT_COND(-1, ! is_sted_set, os << set);
	TOOLS_CK(is_sted_set);

	
	row_index s_idx = set.last_idx();
	row<obj_t>::set_cap(row<obj_t>::size() + set.size());

	row_index m_idx = row<obj_t>::last_idx();
	minc_sz(set.size());
	row_index a_idx = row<obj_t>::last_idx();

	while(s_idx >= 0){
		obj_t& s_obj = set[s_idx];
		s_idx--;
		TOOLS_CK((s_idx < 0) || (cmp_fn(set[s_idx], s_obj) < 0));
		comparison cmp_val = 1;
		while((m_idx >= 0) && 
			((cmp_val = cmp_fn(s_obj, row<obj_t>::pos(m_idx))) < 0))
		{
			row<obj_t>::swap(m_idx, a_idx);
			m_idx--;
			a_idx--;
		}
		TOOLS_CK((m_idx < 0) || (cmp_val > 0));
		row<obj_t>::pos(a_idx) = s_obj;
		a_idx--;
	}

	DBG(is_sted = row<obj_t>::is_sorted(cmp_fn));
	//DBG_PRT_COND(-1, ! is_sted, os << *this);
	TOOLS_CK(is_sted);
}

template<class obj_t>
void
row<obj_t>::sorted_set_reduce(row<obj_t>& set, cmp_func_t cmp_fn){
	if(set.is_empty()){
		return;
	}
	DBG(bool is_sted = row<obj_t>::is_sorted(cmp_fn));
	//DBG_PRT_COND(-1, ! is_sted, os << *this);
	TOOLS_CK(is_sted);
	DBG(bool is_sted_set = set.is_sorted(cmp_fn));
	//DBG_PRT_COND(-1, ! is_sted_set, os << set);
	TOOLS_CK(is_sted_set);

	row_index s_idx = 0;
	row_index d_idx = 0;
	long num_reds = 0;

	while(s_idx < set.size()){
		TOOLS_CK(d_idx < row<obj_t>::size());
		comparison cmp_val;
		while((cmp_val = cmp_fn(set[s_idx], row<obj_t>::pos(d_idx))) > 0){
			if(num_reds > 0){
				row<obj_t>::pos(d_idx - num_reds) = row<obj_t>::pos(d_idx);
			}
			d_idx++;
			TOOLS_CK(d_idx < row<obj_t>::size());
		}
		TOOLS_CK(cmp_val == 0);
		num_reds++;
		d_idx++;
		s_idx++;
	}
	while(d_idx < row<obj_t>::size()){
		TOOLS_CK(num_reds > 0);
		row<obj_t>::pos(d_idx - num_reds) = row<obj_t>::pos(d_idx);
		d_idx++;
	}
	row<obj_t>::clear(true, false, d_idx - num_reds);

	DBG(is_sted = row<obj_t>::is_sorted(cmp_fn));
	//DBG_PRT_COND(-1, ! is_sted, os << *this);
	TOOLS_CK(is_sted);
}


template<class obj_t>
long	
row<obj_t>::shuffle(row_index from, bool init_random){

	row<obj_t> tmp_bag;

	long old_sz = row<obj_t>::size();

	row<obj_t>::copy_to(tmp_bag, from);
	row<obj_t>::clear(true, false, from);

	long seed = 0;
	if(init_random){
		seed = init_random_nums();
	}
	while(tmp_bag.size() > 0){
		long idx_pop = gen_random_num(0, tmp_bag.size());
		TOOLS_CK(idx_pop >= 0);
		TOOLS_CK(idx_pop < tmp_bag.size());
		obj_t var = tmp_bag.swap_pop(idx_pop);
		row<obj_t>::push(var);
	}

	TOOLS_CK(row<obj_t>::size() == old_sz);

	return seed;
}

template<class obj_t>
void
row<obj_t>::mix_sort(cmp_func_t cmp_fn){
	if(SZ_ATTRIB < SELEC_SORT_LIM){
		selec_sort(cmp_fn);
	} else {
		heap<obj_t> he1(*this, cmp_fn);
		he1.hsort();
		he1.move_to(*this);
	}
}

template<class obj_t>
void
heap<obj_t>::build(){
	for(row_index ii = (SZ_ATTRIB)/2; ii >= 0; ii--){ heapify(ii);	}
}

template<class obj_t>
row_index
heap<obj_t>::heapify(row_index idx){
	bool go_on = true;
	do{
		go_on = false;
		row_index lft = left(idx);
		row_index rgt = right(idx);
		row_index maxx = idx;
		if((lft < SZ_ATTRIB) && (cmp(lft, maxx) > 0)){ maxx = lft; } 
		if((rgt < SZ_ATTRIB) && (cmp(rgt, maxx) > 0)){ maxx = rgt; }
		if(maxx != idx){
			row_data<obj_t>::swap(idx, maxx); // r_f
			update_idx(idx);
			update_idx(maxx);
			idx = maxx;
			go_on = true;
		}
	}while(go_on);
	return idx;
};

template<class obj_t>
row_index
heap<obj_t>::changed_key(row_index idx){
	row_index ii = idx, pp = parent(idx);
	obj_t the_obj = row<obj_t>::pos(idx);
	ck_idx(idx);
	for(; (ii > 0) && (pp >= 0) && (cmp_obj(pp, the_obj) < 0); ii = pp, pp = parent(ii)){
		row<obj_t>::pos(ii) = row<obj_t>::pos(pp);  // r_f
		update_idx(ii);
	}
	row<obj_t>::pos(ii) = the_obj;  // r_f
	update_idx(ii);
	idx = heapify(ii);
	return idx;
};

template<class obj_t>
row_index
heap<obj_t>::insert(obj_t n_obj){
	row_data<obj_t>::inc_sz();
	TOOLS_CK((func_idx == NULL_PT) || ((*func_idx)(n_obj) == INVALID_IDX));
	row<obj_t>::pos(SZ_ATTRIB - 1) = n_obj;  // r_f
	update_idx(SZ_ATTRIB - 1);
	return changed_key(SZ_ATTRIB - 1);
};

template<class obj_t>
obj_t
heap<obj_t>::pop_top(){
	obj_t resp = obj_t();
	if(SZ_ATTRIB == 0){ return resp; }
	resp = row<obj_t>::pos(0);
	if(func_idx != NULL_PT){ (*func_idx)(resp) = INVALID_IDX; }

	row<obj_t>::pos(0) = row<obj_t>::pos(SZ_ATTRIB - 1);  // r_f
	update_idx(0);
	(SZ_ATTRIB)--;
	heapify(0);
	return resp;
};

template<class obj_t>
obj_t
heap<obj_t>::remove(row_index idx){
	if(SZ_ATTRIB == 0){ return obj_t(); }
	obj_t obj = row_data<obj_t>::swap_pop(idx);  // r_f
	if(func_idx != NULL_PT){ (*func_idx)(obj) = INVALID_IDX; }

	update_idx(idx);
	changed_key(idx);
	return obj;
};

template<class obj_t>
std::ostream&
heap<obj_t>::print_heap(std::ostream& os, row_index idx){
	row_index lin = 1;
	for(row_index ii = 0; ii < SZ_ATTRIB; ii++){
		if(ii == lin){
			os << "\n";
			lin = left(lin);
		}
		os << row<obj_t>::pos(ii);
		if(func_idx != NULL_PT){ os << "@" << (*func_idx)(row<obj_t>::pos(ii)); } 
		os << " ";
	}
	os << "\nEOT\n";
	return os;
}

template<class obj_t>
bool		
heap<obj_t>::dbg_is_heap_ok(row_index idx){
	row_index lft = left(idx);
	row_index rgt = right(idx);
	row_index maxx = idx;
	if((lft < SZ_ATTRIB) && (cmp(lft, maxx) > 0)){ maxx = lft; } 
	if((rgt < SZ_ATTRIB) && (cmp(rgt, maxx) > 0)){ maxx = rgt; }
	if(maxx != idx){	return false; }
	if((func_idx != NULL_PT) && (idx != (*func_idx)(row<obj_t>::pos(idx)))){	
		return false; 
	}
	if((lft < SZ_ATTRIB) && !dbg_is_heap_ok(lft)){ return false; }
	if((rgt < SZ_ATTRIB) && !dbg_is_heap_ok(rgt)){ return false; }
	return true;
}

//======================================================================
// Relation operators -- extend definitions from '==' and '<'


#ifndef __SGI_STL_INTERNAL_RELOPS   // (be aware of SGI's STL implementation...)
#define __SGI_STL_INTERNAL_RELOPS
template <class obj_t> static inline bool operator != (const obj_t& x, const obj_t& y) { return !(x == y); }
template <class obj_t> static inline bool operator >  (const obj_t& x, const obj_t& y) { return y < x;     }
template <class obj_t> static inline bool operator <= (const obj_t& x, const obj_t& y) { return !(y < x);  }
template <class obj_t> static inline bool operator >= (const obj_t& x, const obj_t& y) { return !(x < y);  }
#endif

//======================================================================

#endif		// TOOLS_H

