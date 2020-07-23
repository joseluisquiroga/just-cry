

/*************************************************************

bit_row.h  
(C 2007) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

binary rows of bits.

last update: 29 Ago 2007.

--------------------------------------------------------------*/


#ifndef BIT_ROW_H
#define BIT_ROW_H

#include "mem.h"

typedef long		bit_row_index;

#ifndef INVALID_IDX
#define INVALID_IDX		-1
#endif

#ifndef FILL_FULL_CAP
#define FILL_FULL_CAP	-100
#endif

#ifndef START_CAP
#define START_CAP 		16	// avoid mem problems (due to malloc, realloc failures)
#endif

#ifndef k_num_bits_byte
#define k_num_bits_byte		8
#endif

#define BITS_CK(prm)	   	DBG_CK(prm)

enum bit_row_exception_code { 
	k_bit_row_01_exception = k_last_mem_exception,
	k_bit_row_02_exception,
	k_last_bit_row_exception
};

//======================================================================
// bitarray

// where 'a' is the byte stream pointer, and b is the bit number.

#define div8(b)	((b)>>3)
#define mod8(b)	((b)&7)

#define get_bit(a, b)		((((t_1byte*)a)[div8(b)] >> mod8(b)) & 1)
#define set_bit(a, b)		(((t_1byte*)a)[div8(b)] |= (1 << mod8(b)))
#define reset_bit(a, b) 	(((t_1byte*)a)[div8(b)] &= ~(1 << mod8(b)))
#define toggle_bit(a, b) 	(((t_1byte*)a)[div8(b)] ^= (1 << mod8(b)))

#define to_bytes(num_bits)	(div8(num_bits) + (mod8(num_bits) > 0))
#define to_bits(num_bytes)	(num_bytes * k_num_bits_byte)

//======================================================================
// bit_row

class bit_row;

class bit_ref {
public:
	bit_row_index	idx;
	bit_row*	brow;
	
	bit_ref(){
		idx = 0;
		brow = NULL_PT;
	}
	
	bit_ref&  operator = (bool val);
	operator bool();
};

bit_row_index
rot_lft_idx(bit_row_index pos, bit_row_index row_sz, long num_rot);

bit_row_index 
rot_rgt_idx(bit_row_index pos, bit_row_index row_sz, long num_rot);

std::ostream&	operator << (std::ostream& os, bit_row& rr);
bit_row&	operator << (bit_row& rr, const bool elem);
bit_row&	operator >> (bit_row& rr, bool& elem);
bit_row&	operator << (bit_row& rr1, bit_row& rr2);

class bit_row {
private:
	// Don't allow copying (error prone):
	// force use of referenced rows

	bit_row&  operator = (bit_row& other){
		MARK_USED(other);
		error_code_t err_cod = k_bit_row_01_exception;
		DBG_THROW(k_bit_row_01_exception != k_bit_row_01_exception);
		throw err_cod;
		std::cerr << "FATAL ERROR. Memory exhausted" << std::endl;
		abort_func(0);
		return (*this);
	}

	bit_row(bit_row& other){ 
		MARK_USED(other);
		error_code_t err_cod = k_bit_row_02_exception;
		DBG_THROW(k_bit_row_02_exception != k_bit_row_02_exception);
		throw err_cod;
		std::cerr << "FATAL ERROR. Memory exhausted" << std::endl;
		abort_func(0);
	}

public:
	bit_row_index	cap;	// num bytes of cap
	bit_row_index	sz;		// num bits in arr
	t_1byte*	data;

	bit_row(){
		sz = 0;
		cap = 0;
		data = NULL_PT;
	}

	~bit_row(){
		clear(true, true);
	}

	bit_row_index	get_cap(){
		return to_bits(cap);
	}

	bit_row_index	get_bytes_cap(){
		return cap;
	}

	virtual
	void	grow(bit_row_index bits_cap){
		bit_row_index min_cap = to_bytes(bits_cap);
		if(min_cap <= cap){ return; }
		bit_row_index nxt_cap = cap;

		if(nxt_cap == 0){ 
			nxt_cap = to_bytes(START_CAP); 
		}

		do{ 
			nxt_cap = nxt_cap * 2; 
		} while(nxt_cap < min_cap);

		BITS_CK(nxt_cap > 1);
		set_cap(to_bits(nxt_cap));
	}

	virtual
	void	set_cap(bit_row_index bits_cap){ 
		bit_row_index min_cap = to_bytes(bits_cap);
		if(min_cap <= cap){ return; }
		bit_row_index old_cap = cap;
		BITS_CK(old_cap >= 0);
		cap = min_cap;
		t_1byte* n_dat = tpl_realloc(data, old_cap, cap);
		data = n_dat;
	}

	virtual
	void	set_size(bit_row_index bits_sz){ 
		set_cap(bits_sz);
		sz = bits_sz;
	}

	virtual
	void	clear(bool reset_them = false, bool dealloc = false, bit_row_index from = 0){ 
		if(data != NULL_PT){
			if(from != 0){
				dealloc = false;
			}
			if(dealloc){
				reset_them = false;
			}
			if(reset_them){ 
				for(bit_row_index ii = from; ii < sz; ii++){ 
					reset_bit(data, ii);
				}
			}
			sz = from;
			if(dealloc){ 
				tpl_free(data, cap);
				data = NULL_PT;
				cap = 0; 
			}
		} 
	}

	bit_row_index	size() const { 
		return sz; 
	}

	bit_row_index	num_bytes() const { 
		return to_bytes(sz); 
	}

	bool		is_full() { 
		return (sz == get_cap()); 
	}

	bool	is_empty(){
		return (sz == 0);
	}

	bool	pos(bit_row_index idx){ 
		return get_bit(data, idx);
	}

	void	set(bit_row_index idx){ 
		set_bit(data, idx);
	}

	void	reset(bit_row_index idx){ 
		reset_bit(data, idx);
	}

	void	set_val(bit_row_index idx, bool val = false){ 
		if(val){
			set_bit(data, idx);
		} else {
			reset_bit(data, idx);
		}
	}

	virtual
	void	push(const bool elem){ 
		if(is_full()){ 
			grow(sz + 2); 
		}
		set_val(sz, elem);
		sz++; 
	}

	virtual
	void	inc_sz(){ 
		if(is_full()){ 
			grow(sz + 2);
		}
		reset_bit(data, sz);
		sz++; 
	}

	virtual
	void	dec_sz(){ 
		sz--; 
		reset_bit(data, sz);
	}

	virtual
	bool	pop(){ 
		BITS_CK(sz > 0);
		sz--; 
		bool tmp1 = pos(sz);
		reset_bit(data, sz);
		return tmp1; 
	}

	bool	last(){ 
		return pos(sz - 1); 
	}

	void	swap(bit_row_index idx1, bit_row_index idx2){ 
		bool tmp1 = pos(idx1);
		set_val(idx1, pos(idx2));
		set_val(idx2, tmp1);
	}

	virtual
	bool	swap_pop(bit_row_index idx){
		bool tmp1 = pos(idx);
		sz--;
		set_val(idx, pos(sz));
		reset_bit(data, sz);
		return tmp1;
	}

	virtual
	void	swapop(bit_row_index idx){ 
		sz--;
		set_val(idx, pos(sz));
		reset_bit(data, sz);
	}

	void	fill(const bool elem, bit_row_index num_fill = INVALID_IDX){ 
		if(num_fill == INVALID_IDX){
			num_fill = sz;
		}
		if(num_fill == FILL_FULL_CAP){
			num_fill = get_cap();
		}
		set_cap(num_fill);
		bit_row_index ii = 0;
		for(ii = 0; ((ii < sz) && (ii < num_fill)); ii++){
			set_val(ii, elem);
		}
		for(; ii < num_fill; ii++){
			push(elem);
		}
	}

	void	fill_new(bit_row_index num_fill = INVALID_IDX){ 
		clear(true);
		if(num_fill == INVALID_IDX){
			num_fill = sz;
		}
		if(num_fill == FILL_FULL_CAP){
			num_fill = get_cap();
		}
		set_cap(num_fill);
		for(bit_row_index ii = 0; ii < num_fill; ii++){
			inc_sz();
		}
	}

	bit_ref    operator [] (bit_row_index idx)        { 
		BITS_CK(idx >= 0);
		BITS_CK(idx < sz);
		bit_ref the_ref;
		the_ref.brow = this;
		the_ref.idx = idx;
		return the_ref; 
	}

    void copy_to(bit_row& r_cpy, bit_row_index first_ii = 0, bit_row_index last_ii = -1){ 
		r_cpy.clear(true, false); 
		if((last_ii < 0) || (last_ii > sz)){
			last_ii = sz;
		}
		if((first_ii < 0) || (first_ii > last_ii)){
			first_ii = 0;
		}
		r_cpy.set_cap(last_ii - first_ii); 
		for (bit_row_index ii = first_ii; ii < last_ii; ii++){
			bool ob = pos(ii);
			r_cpy.push(ob);
		}
	}

    void append_to(bit_row& orig){ 
		orig.set_cap(orig.sz + sz); 
		for (bit_row_index ii = 0; ii < sz; ii++){
			orig.push(pos(ii));
		}
	}

	// rotation funcs

	void rotate_left(bit_row& dest, long num_bits){
		dest.set_size(size());
		BITS_CK(size() == dest.size());
		long d_sz = dest.size();
		for(bit_row_index aa = 0; aa < size(); aa++){
			bit_row_index d_idx = rot_lft_idx(aa, d_sz, num_bits);
			dest[d_idx] = pos(aa);
		}
	}

	void rotate_right(bit_row& dest, long num_bits){
		dest.set_size(size());
		BITS_CK(size() == dest.size());
		long d_sz = dest.size();
		for(bit_row_index aa = 0; aa < size(); aa++){
			bit_row_index d_idx = rot_rgt_idx(aa, d_sz, num_bits);
			dest[d_idx] = pos(aa);
		}
	}

	// io funcs

	std::ostream&	print_bit_row(
		std::ostream& os, 
		bool with_lims = true,
		std::string sep = " ", 
		bit_row_index low = INVALID_IDX, 
		bit_row_index hi = INVALID_IDX,
		bit_row_index grp_sz = -1,
		std::string grp_sep = "\n"
		)
	{
		bit_row_index num_elem = 1;
		if(with_lims){ os << "["; }
		for(bit_row_index ii = 0; ii < sz; ii++){
			if(ii == low){ os << ">"; }
			os << pos(ii);
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

	bool	equal_to(bit_row& rw2, bit_row_index first_ii = 0, bit_row_index last_ii = -1){
		if((last_ii < 0) || (last_ii > sz)){
			last_ii = sz;
		}
		if((first_ii < 0) || (first_ii > last_ii)){
			first_ii = 0;
		}
		//for(bit_row_index ii = 0; ii < sz; ii++){
		for (bit_row_index ii = first_ii; ii < last_ii; ii++){
			if(pos(ii) != rw2.pos(ii)){
				return false;
			}
		}
		return true;
	}

	void move_to(bit_row& dest, bool just_init = false){ 
		if(!just_init){ 
			dest.clear(true, true); 
		}
		dest.data = data; 
		dest.sz = sz; 
		dest.cap = cap; 
		data = NULL_PT; 
		sz = 0; 
		cap = 0; 
	}

    void mem_copy_to(bit_row& r_cpy){ 
		r_cpy.set_cap(sz);
		memcpy(r_cpy.data, data, r_cpy.cap);
		r_cpy.sz = sz;
	}
};

inline
bit_ref& bit_ref::operator = (bool val){
	BITS_CK(brow != NULL_PT);
	brow->set_val(idx, val);
	return (*this);
}

inline
bit_ref::operator bool(){
	BITS_CK(brow != NULL_PT);
	return brow->pos(idx);
}

inline
bit_row_index
rot_lft_idx(bit_row_index pos, bit_row_index row_sz, long num_rot){
	//long r_rot = row_sz - (num_rot % row_sz);
	long r_rot = (num_rot % row_sz);
	bit_row_index n_idx = (pos - r_rot);
	if(n_idx < 0){
		n_idx = row_sz + n_idx;
	}
	BITS_CK(n_idx >= 0);
	BITS_CK(n_idx < row_sz);
	return n_idx;
}

inline
bit_row_index 
rot_rgt_idx(bit_row_index pos, bit_row_index row_sz, long num_rot){
	//long r_rot = row_sz - (num_rot % row_sz);
	long r_rot = (num_rot % row_sz);
	bit_row_index n_idx = (pos + r_rot);
	if(n_idx >= row_sz){
		n_idx = n_idx % row_sz;
	}
	BITS_CK(n_idx >= 0);
	BITS_CK(n_idx < row_sz);
	return n_idx;
}

inline 
std::ostream&	operator << (std::ostream& os, bit_row& rr){
	rr.print_bit_row(os, true, " ");
	return os;
}

inline
bit_row&	operator << (bit_row& rr, const bool elem){
	rr.push(elem);
	return rr;
}

inline
bit_row&	operator >> (bit_row& rr, bool& elem){
	elem = rr.pop();
	return rr;
}

inline
bit_row&	operator << (bit_row& rr1, bit_row& rr2){
	rr2.append_to(rr1);
	return rr1;
}

//======================================================================
// s_bit_row

// careful: cannot free the given data while using the 
// s_bit_row object because it is a pointer to the given data. 

class s_bit_row : public bit_row {
private:
	virtual
	void	grow(bit_row_index bits_cap){ MARK_USED(bits_cap); }
	virtual
	void	set_cap(bit_row_index bits_cap){ MARK_USED(bits_cap); }
	virtual
	void	set_size(bit_row_index bits_sz){ MARK_USED(bits_sz); }
	virtual
	void	push(const bool elem){ MARK_USED(elem); }
	virtual
	void	inc_sz(){}
	virtual
	void	dec_sz(){}
	virtual
	bool	pop(){ return false; }
	virtual
	bool	swap_pop(bit_row_index idx){ MARK_USED(idx); return false; }
	virtual
	void	swapop(bit_row_index idx){ MARK_USED(idx); }

public:
	virtual
	void	clear(bool reset_them = false, bool dealloc = false, bit_row_index from = 0){
		MARK_USED(reset_them);
		MARK_USED(dealloc);
		MARK_USED(from);
		sz = 0;
		cap = 0;
		data = NULL_PT;
	} 

	s_bit_row(t_1byte* dat = NULL_PT, long dat_num_bytes = 0){
		init_data(dat, dat_num_bytes);
	}

	s_bit_row(double* dat){
		init_data((t_1byte*)dat, sizeof(double));
	}

	s_bit_row(long* dat){
		init_data((t_1byte*)dat, sizeof(long));
	}

	s_bit_row(char* dat){
		init_data((t_1byte*)dat, sizeof(char));
	}

	s_bit_row(s_bit_row& bt_r, long from_byte, 
			long num_bytes)
	{
		long max_byte = bt_r.get_bytes_cap();
		if(from_byte > max_byte){
			from_byte = max_byte;
		} 
		if((from_byte + num_bytes) > max_byte){
			num_bytes = (max_byte - from_byte);
		}
		t_1byte* dat = bt_r.data + from_byte;
		init_data(dat, num_bytes);
	}

	~s_bit_row(){
		clear();
	}

	void init_data(t_1byte* dat, long dat_num_bytes){
		sz = to_bits(dat_num_bytes);
		cap = dat_num_bytes;
		if(cap > 0){
			data = dat;
		} else {
			data = NULL_PT;
		}
	}

};

#endif		// BIT_ROW_H
