

/*************************************************************

cry.h  
(C 2025) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

Base classes and abstract data types to code the system.

--------------------------------------------------------------*/


#ifndef CRY_H
#define CRY_H

#include <cmath>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>

#include "bit_row.h"
#include "tools.h"
#include "secure_gets.h"
#include "tak_mak.h"

#define CRY_CK(prm)	   DBG_CK(prm)

#ifndef CARRIAGE_RETURN
#define CARRIAGE_RETURN		((char)13)
#endif

#define NUM_BITS_IN_BYTE 8

#define MIN_KEY_INIT_CHANGES 1000
#define MAX_KEY_INIT_CHANGES 2000

#define MAX_REFLEX_OPER 4

#define NUM_BYTES_SHA2	32	// 256 bits

#define fst_long(pt_dat) (*((long*)pt_dat))

#define pt_as(pt_dat, tp_dat) (*((tp_dat*)pt_dat))

#define wrt_val(stm, val) stm.write((char*)(&val), sizeof(val))
#define rd_val(stm, val) stm.read((char*)(&val), sizeof(val))

extern char* version_msg;

bool	open_ifile(const char* in_nm, std::ifstream& in_stm);
ch_string sha_txt_of_arr(uchar_t* to_sha, long to_sha_sz);


class cry_encryptor {
private:
	std::ifstream			input_stm;

	bool				bits_part;

	tak_mak				for_key;
	tak_mak				for_bytes_dest;
	tak_mak				for_bits_dest;
	tak_mak				for_bits_src;
	tak_mak				for_byte_flx;

	s_bit_row			key_bits;
	s_row<unsigned long>		key_longs;

	secure_row<char>	sw_aux;
	secure_row<long>	sw_dest;

	t_1byte*			pt_file_data;
	long				file_data_sz;

	s_row<t_1byte>		target_bytes;
	s_bit_row			target_bits;

public:
	bool				with_sha;
	bool				encry;
	bool				as_hex;
	bool				just_sha;

	ch_string			input_file_nm;
	secure_row<t_1byte>		key;
	
	ch_string			target_sha;

	bool				prt_help;
	bool				prt_version;

	cry_encryptor(){
		input_file_nm = "";
		bits_part = false;

		with_sha = true;
		encry = true;
		as_hex = false;
		just_sha = false;
		
		pt_file_data = NULL_PT;
		file_data_sz = 0;
		
		target_sha = "";

		prt_help = false;
		prt_version = false;
	}

	~cry_encryptor(){
		end_target();
	}

	void	end_target(){
		if(pt_file_data != NULL_PT){
			memset(pt_file_data, 0, file_data_sz);
			free(pt_file_data);
			pt_file_data = NULL_PT;
			file_data_sz = 0;

			target_bytes.clear();
			target_bits.clear();
		}
	}

	bool	has_target(){
		return (! target_bytes.is_empty());
	}

	bool	has_key(){
		return (! key_longs.is_empty());
	}

	tak_mak&	get_tm(){
		tak_mak* tm = NULL_PT;
		if(bits_part){
			tm = &for_bits_dest;
		} else {
			tm = &for_bytes_dest;
		}
		CRY_CK(tm != NULL_PT);
		return *tm;
	}

	long	get_limit_idx(){
		if(bits_part){
			return target_bits.size();
		} else {
			return target_bytes.size();
		}
	}

	long	gen_oper(tak_mak& tm_gen, long limit_idx);

	long	chr_row_to_long(row<char>& rr);

	void	fill_limits(secure_row<char>& tmp_str,
				long& num_1, long& num_2);

	void	add_key_section(s_row<char>& file_bytes, 
				secure_row<char>& tmp_key, 
				long num1, long num2);

	void	ask_key(secure_row<t_1byte>& the_key);
	void	get_key(secure_row<t_1byte>& the_key);
	void	init_key();

	void 	init_tak_mak_with_key(tak_mak& tm){
		if(key_longs.size() == 1){
			tm.init_with_long(key_longs[0]);
		} else {
			tm.init_with_array(key_longs.get_c_array(), key_longs.get_c_array_sz());
		}
	}
	
	void 	shake_key_with(tak_mak& tm);
	void	init_tak_maks();
	void	init_target_encry();
	void	init_target_decry();
	
	void	init_rf_aux(){
		tak_mak& tm_gen = for_byte_flx;

		sw_aux.set_size(target_bytes.size());
		for(long aa = 0; aa < target_bytes.size(); aa++){
			sw_aux[aa] = gen_oper(tm_gen, MAX_REFLEX_OPER);
		}
		CRY_CK(target_bytes.size() == sw_aux.size());
	}

	void	init_sw_aux(){
		tak_mak& tm_gen = for_bits_src;
		CRY_CK((bit_row_index)(target_bytes.size() * NUM_BITS_IN_BYTE) == target_bits.size());

		sw_aux.set_size(target_bytes.size());
		for(long aa = 0; aa < target_bytes.size(); aa++){
			char src_idx = gen_oper(tm_gen, NUM_BITS_IN_BYTE);
			CRY_CK(src_idx >= 0);
			CRY_CK(src_idx < NUM_BITS_IN_BYTE);
			long bt_src = (aa * NUM_BITS_IN_BYTE) + sw_aux[aa];
			CRY_CK(bt_src >= 0);
			CRY_CK(bt_src < target_bits.size());
			sw_aux[aa] = src_idx;
			//std::cout << "    " << pct_bit_idx(src_idx);
		}
		CRY_CK(target_bytes.size() == sw_aux.size());
	}
	
	void	init_sw_dest(){
		tak_mak& tm_gen = get_tm();
		long limit_idx = get_limit_idx();

		sw_dest.set_size(target_bytes.size());
		for(long aa = 0; aa < target_bytes.size(); aa++){
			sw_dest[aa] = gen_oper(tm_gen, limit_idx);
		}
		CRY_CK(target_bytes.size() == sw_dest.size());
	}

	void	byte_swap(long num_oper){
		long by_src = num_oper;
		long by_dest = sw_dest[num_oper];
		target_bytes.swap(by_dest, by_src);
	}

	double 	pct_bit_idx(long idx){
		return (((double)idx * 100.0)/ (double)target_bits.size());
	}

	void	bit_swap(long num_oper){
		//long bt_src = num_oper; // FIX. ONLY SWAPS BITS in the first target_bytes.size() BITS !!!
		long bt_src = (num_oper * NUM_BITS_IN_BYTE) + sw_aux[num_oper];
		long bt_dest = sw_dest[num_oper];
		//std::cout << "    " << pct_bit_idx(bt_src) << "-" << pct_bit_idx(bt_dest);
		target_bits.swap(bt_dest, bt_src);
	}

	t_1byte	byte_full_invert(t_1byte by_tgt){
		t_1byte by_rflx = by_tgt;
		s_bit_row op_bits(&by_rflx, true);
		op_bits.swap(0,7);
		op_bits.swap(1,6);
		op_bits.swap(2,5);
		op_bits.swap(3,4);
		return by_rflx;
	}
	
	t_1byte	byte_halfs_invert(t_1byte by_tgt){
		t_1byte by_rflx = by_tgt;
		s_bit_row op_bits(&by_rflx, true);
		op_bits.swap(0,3);
		op_bits.swap(1,2);
		op_bits.swap(4,7);
		op_bits.swap(5,6);
		return by_rflx;
	}
	
	t_1byte	byte_hi_lo_swap(t_1byte by_tgt){
		t_1byte by_rflx = by_tgt;
		s_bit_row op_bits(&by_rflx, true);
		op_bits.swap(0,4);
		op_bits.swap(1,5);
		op_bits.swap(2,6);
		op_bits.swap(3,7);
		return by_rflx;
	}
	
	void	byte_reflex(long num_oper){
		char by_rf_op = sw_aux[num_oper];
		t_1byte by_tgt = target_bytes[num_oper];
		t_1byte by_rflx = by_tgt;
		switch(by_rf_op){
			case 0:
				by_rflx = byte_full_invert(by_tgt);
				break;
			case 1:
				by_rflx = byte_halfs_invert(by_tgt);
				break;
			case 2:
				by_rflx = byte_hi_lo_swap(by_tgt);
				break;
		}
		target_bytes[num_oper] = by_rflx;
	}

	void	encry_bytes(){
		CRY_CK(encry);
		CRY_CK(! target_bytes.is_empty());
		bits_part = false;
		init_sw_dest();
		for(long aa = 0; aa < target_bytes.size(); aa++){
			byte_swap(aa);
		}
	}

	void	encry_bits(){
		CRY_CK(encry);
		CRY_CK(! target_bits.is_empty());
		bits_part = true;
		init_sw_aux();
		init_sw_dest();
		for(long aa = 0; aa < target_bytes.size(); aa++){
			bit_swap(aa);
		}
	}

	void	encry_reflex(){
		CRY_CK(encry);
		CRY_CK(! target_bytes.is_empty());
		bits_part = false;
		init_rf_aux();
		for(long aa = 0; aa < target_bytes.size(); aa++){
			byte_reflex(aa);
		}
	}

	void	decry_bytes(){
		CRY_CK(! encry);
		bits_part = false;
		init_sw_dest();
		for(long aa = (target_bytes.size() - 1); aa >= 0; aa--){
			byte_swap(aa);
		}
	}

	void	decry_bits(){
		CRY_CK(! encry);
		bits_part = true;
		init_sw_aux();
		init_sw_dest();
		for(long aa = (target_bytes.size() - 1); aa >= 0; aa--){
			bit_swap(aa);
		}
	}

	void	decry_reflex(){
		CRY_CK(! encry);
		bits_part = false;
		init_rf_aux();
		for(long aa = (target_bytes.size() - 1); aa >= 0; aa--){
			byte_reflex(aa);
		}
	}

	void	process_target(){
		if(! has_key() || ! has_target()){
			return;
		}
		if(encry){
			encry_bytes();
			encry_bits();
			encry_reflex();
		} else {
			decry_reflex();
			decry_bits();
			decry_bytes();
		}
	}

	void	write_output(){
		if(! has_key() || ! has_target()){
			return;
		}
		ch_string o_nm;
		ch_string encry_ext = ".encry";
		if(encry){
			o_nm = input_file_nm + encry_ext;
			write_encry_file(o_nm.c_str());
		} else {
			long i_sz = input_file_nm.size();
			//long pos_ext = i_sz - strlen(encry_ext);
			long pos_ext = i_sz - encry_ext.length();
			if(pos_ext > 0){
				o_nm = input_file_nm.substr(0, (i_sz - pos_ext));
			}
			o_nm = input_file_nm + ".decry";
			write_decry_file(o_nm.c_str());
		}
	}

	void	write_encry_file(const char* out_nm);
	void	write_decry_file(const char* out_nm);

	void	init_input(){
		std::ostream& os = std::cout;

		if(input_file_nm.size() == 0){
			return;
		}

		const char* f_nm = input_file_nm.c_str();  
		if(! open_ifile(f_nm, input_stm)){
			os << "Could not open input file '" 
				<< input_file_nm << "'" << std::endl;
		}
	}

	bool	has_input(){
		return (input_stm.good() && input_stm.is_open());
	}
	
	void 	set_info_header_encry(row<char>& txt_hd, ch_string& data_sha, long data_size);
	void 	get_info_header_decry(s_row<t_1byte>& tgt, ch_string& data_sha, char*& pt_data, long& data_sz);
	
	void 	print_sha();

	void	process_file(){
		CRY_CK(sizeof(t_1byte) == sizeof(unsigned char));
		CRY_CK(sizeof(t_1byte) == sizeof(char));

		init_input();
		if(! encry){
			init_target_decry();
		}
		init_key();
		init_tak_maks();
		if(encry){
			init_target_encry();
		}
		process_target();
		write_output();
	}

	void	get_args(int argc, char** argv);
};


#endif  // CRY_H
