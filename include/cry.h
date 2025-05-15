

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

#define MIN_KEY_INIT_CHANGES 1000
#define MAX_KEY_INIT_CHANGES 2000

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
	tak_mak				for_bytes;
	tak_mak				for_bits;

	s_bit_row			key_bits;
	s_row<unsigned long>		key_longs;

	secure_row<long>	opers;

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
			tm = &for_bits;
		} else {
			tm = &for_bytes;
		}
		CRY_CK(tm != NULL_PT);
		return *tm;
	}

	long	get_max_op(){
		if(bits_part){
			return target_bits.size();
		} else {
			return target_bytes.size();
		}
	}

	long	gen_oper(tak_mak& tm_gen, long max_op);

	long	chr_row_to_long(row<char>& rr);

	void	fill_limits(secure_row<char>& tmp_str,
				long& num_1, long& num_2);

	void	add_key_section(s_row<char>& file_bytes, 
				secure_row<char>& tmp_key, 
				long num1, long num2);

	void	ask_key(secure_row<t_1byte>& the_key);
	void	get_key(secure_row<t_1byte>& the_key);
	void	init_key();

	void	init_tak_maks();
	void	init_target_encry();
	void	init_target_decry();

	void	init_opers(){
		tak_mak& tm_gen = get_tm();
		long max_op = get_max_op();

		opers.set_size(target_bytes.size());
		for(long aa = 0; aa < target_bytes.size(); aa++){
			opers[aa] = gen_oper(tm_gen, max_op);
		}
	}

	void	byte_oper(long oper){
		long v_op = opers[oper];
		target_bytes.swap(v_op, oper);
	}

	void	bit_oper(long oper){
		long v_op = opers[oper];
		target_bits.swap(v_op, oper);		// FIX. ONLY SWAPS BITS in the first target_bytes.size() BITS !!!
	}

	void	encry_bytes(){
		CRY_CK(encry);
		CRY_CK(! target_bytes.is_empty());
		bits_part = false;
		init_opers();
		for(long aa = 0; aa < opers.size(); aa++){
			byte_oper(aa);
		}
	}

	void	encry_bits(){
		CRY_CK(encry);
		CRY_CK(! target_bits.is_empty());
		bits_part = true;
		init_opers();
		for(long aa = 0; aa < opers.size(); aa++){
			bit_oper(aa);
		}
	}

	void	decry_bytes(){
		CRY_CK(! encry);
		bits_part = false;
		init_opers();
		for(long aa = (opers.size() - 1); aa >= 0; aa--){
			byte_oper(aa);
		}
	}

	void	decry_bits(){
		CRY_CK(! encry);
		bits_part = true;
		init_opers();
		for(long aa = (opers.size() - 1); aa >= 0; aa--){
			bit_oper(aa);
		}
	}

	void	process_target(){
		if(! has_key() || ! has_target()){
			return;
		}
		if(encry){
			encry_bytes();
			encry_bits();
			target_sha = sha_txt_of_arr((uchar_t*)target_bytes.get_data(), target_bytes.size());
		} else {
			target_sha = sha_txt_of_arr((uchar_t*)target_bytes.get_data(), target_bytes.size());
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
	
	void 	init_encry_txt_header(row<char>& txt_hd);
	void 	init_decry_txt_header(row<char>& txt_hd);
	
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
