

/*************************************************************

cry.cpp
(C 2025) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

cry encryptor functions. no-trace style encryptor.

--------------------------------------------------------------*/

#include "cry.h"
#include "sha2.h"

typedef std::ostringstream bj_ostr_stream;

DEFINE_MEM_STATS;

char* cry_vr_msg = NULL_PT;
long cry_vr_msg_sz = 0; 

ch_string cry_vr4_msg =
"cry v4\n"
"https://github.com/joseluisquiroga/just-cry\n"
"(c) 2025. QUIROGA BELTRAN, Jose Luis. Bogota - Colombia.\n"
;

ch_string cry_help =
"cry4 <file_name> [-e|-d|-h|-v] [-x][-r]\n"
"\n"
"-e : encrypt the given <file_name>. (default option).\n"
"-d : decrypt the given <file_name>.\n"
"-h : show invocation info.\n"
"-v : show version info.\n"
"\n"
"-x : output as text in hex.\n"
"-r : raw process (-e|-d) the given <file_name>.\n"
"\n"
"See file 'cry_use.txt' in the source directory or\n"
"visit 'https://github.com/joseluisquiroga/just-cry'\n"
;

ch_string cry_info = "cry_use.txt";

ch_string data_sha_field = "data_sha=";
ch_string data_size_field = "data_size=";
ch_string end_header = "<<<END_OF_HEADER>>>\n";

int WITH_SHA_TOP_HEADER_SZ = 500; // num bytes top header

void test_header(cry_encryptor& cry_engine);

bool
open_ifile(const char* in_nm, std::ifstream& in_stm){
	in_stm.open(in_nm, std::ios::binary);
	if(!in_stm.good() || !in_stm.is_open()){
		return false;
	}
	return true;
}

char*	read_file(std::ifstream& in_stm, long& data_sz,
				  long head_sz = 0, long tail_sz = 0)
{
	if(head_sz < 0){ return NULL_PT; }
	if(tail_sz < 0){ return NULL_PT; }

	long file_sz = 0;

	in_stm.seekg (0, std::ios::end);
	file_sz = in_stm.tellg();
	in_stm.seekg (0, std::ios::beg);

	data_sz = (t_dword)file_sz + head_sz + tail_sz;

	CRY_CK(sizeof(char) == 1);
	
	long mem_sz = (data_sz + 1);
	char* file_data = (char*)malloc(mem_sz);

	if(file_data == NULL_PT){ return NULL_PT; }

	CRY_CK(file_data != NULL);
	in_stm.read(file_data + head_sz, file_sz);
	long num_read = in_stm.gcount();

	if(num_read != file_sz){ 
		memset(file_data, 0, mem_sz);
		free(file_data);
		data_sz = 0;
		return NULL_PT; 
	}
	CRY_CK(num_read == file_sz);

	in_stm.close();
	return file_data;
}

ch_string	read_arr_line(char*& pt_data, long& rest_data_sz){
	bj_ostr_stream ss_val;
	while(rest_data_sz > 0){
		char cc = *pt_data;
		ss_val << cc;
		pt_data++;
		rest_data_sz--;
		if(cc == '\n'){
			break;
		}
	}
	return ss_val.str();
}

long	
cry_encryptor::gen_oper(tak_mak& tm_gen, long max_op){
	long op = 0;
	s_bit_row op_bits(&op);

	long idx1 = 0;
	long idx2 = 0;

	op = tm_gen.gen_rand_int32();
	idx1 = tm_gen.gen_rand_int32_ie(0, key_bits.size());
	idx2 = tm_gen.gen_rand_int32_ie(0, op_bits.size());

	op_bits[idx2] = key_bits[idx1];

	op = to_interval(op, 0, max_op);

	CRY_CK((op >= 0) && (op < max_op));
	return op;
}

long
cry_encryptor::chr_row_to_long(row<char>& rr){
	CRY_CK(! rr.is_empty());
	s_bit_row rr_bits;
	rr.init_s_bit_row(rr_bits);

	long ll = 0;
	s_bit_row ll_bits(&ll);
	for(long aa = 0; aa < ll_bits.size(); aa++){
		long pos_rr = for_key.gen_rand_int32_ie(0, rr_bits.size());
		ll_bits[aa] = rr_bits[pos_rr];
	}
	return ll;
}

void
cry_encryptor::fill_limits(secure_row<char>& tmp_str,
			long& num_1, long& num_2)
{
	long val_str = 0;

	tmp_str.push(0);
	val_str = atol(tmp_str.get_data());
	tmp_str.pop();

	if((val_str != 0) && (num_1 < 0)){
		num_1 = val_str;
	} else 
	if((val_str != 0) && (num_2 < 0)){
		num_2 = val_str;
	} else 
	if(	(tmp_str.size() == 1) && 
		(tmp_str[0] == '0'))
	{
		if(num_1 < 0){
			num_1 = 0;
		} else if(num_2 < 0){
			num_2 = 0;
		}
	} else 
	if((val_str == 0) && (num_1 < 0)){
		num_1 = chr_row_to_long(tmp_str);
	} else 
	if((val_str == 0) && (num_2 < 0)){
		num_2 = chr_row_to_long(tmp_str);
	}
}

void
cry_encryptor::add_key_section(s_row<char>& file_bytes, 
			secure_row<char>& tmp_key, long num_1, long num_2)
{
	std::ostream& os = std::cout;

	long max_idx = file_bytes.size() + 1;
	long idx_1 = to_interval(num_1, 0, max_idx);
	long idx_2 = to_interval(num_2, 0, max_idx);

	if(idx_1 == idx_2){
		os << "cry cound not generate a valid section with"
			<< "those values. section ignored." << std::endl;
		return;
	}

	if(idx_1 > idx_2){
		file_bytes.append_to(tmp_key, idx_2, idx_1, true);
	} else {
		CRY_CK(idx_1 < idx_2);
		file_bytes.append_to(tmp_key, idx_1, idx_2); 
	}

	//os << tmp_key << std::endl;
}

void
cry_encryptor::ask_key(secure_row<t_1byte>& the_key){
	std::ostream& os = std::cout;

	secure_row<char>	tmp_key;
	secure_row<char>	tmp_str;
	s_row<char>		file_bytes;

	secure_gets(tmp_str);
	os << " * " << std::endl;

	long key_sz = 0;
	char* key_data = NULL_PT;
	std::ifstream in_stm;

	tmp_str.push(0);
	const char* key_f_nm = tmp_str.get_data();
	if(strcmp(key_f_nm, input_file_nm.c_str()) != 0){
		if(open_ifile(tmp_str.get_data(), in_stm)){
			key_data = read_file(in_stm, key_sz); 
			file_bytes.init_data(key_data, key_sz);
			os << "USING KEY BASE FILE" << std::endl;
		} 
	} else {
		os << "key base file cannot be the target file." << std::endl;
		os << "file ignored. not used as key base file." << std::endl;
	}
	tmp_str.pop();

	if(! tmp_str.is_empty()){
		unsigned long* ini_arr = (unsigned long*)(tmp_str.get_data());
		long ini_arr_sz = (tmp_str.get_data_sz() / sizeof(long));

		for_key.init_with_array(ini_arr, ini_arr_sz);

		if(file_bytes.is_empty()){
			tmp_str.append_to(tmp_key);
		}
	}

	long num_1 = -1;
	long num_2 = -1;
	while(! tmp_str.is_empty()){
		tmp_str.clear();
		os << ">";
		secure_gets(tmp_str);
		os << " * " << std::endl;

		if(! tmp_str.is_empty()){
			if(file_bytes.is_empty()){
				tmp_str.append_to(tmp_key);
			} else {
				fill_limits(tmp_str, num_1, num_2);
				if((num_1 >= 0) && (num_2 >= 0)){
					add_key_section(file_bytes, tmp_key,
							num_1, num_2);
					num_1 = -1; 
					num_2 = -1;
				}
			}
		}
	}

	if(! file_bytes.is_empty()){
		file_bytes.erase_data();
		t_1byte* dat = (t_1byte*)(file_bytes.get_data());
		free(dat);
		file_bytes.clear();
	}

	tmp_key.move_to(the_key);

	os << std::endl;
}

void
cry_encryptor::get_key(secure_row<t_1byte>& the_key){
	secure_row<t_1byte> tmp_key;

	std::ostream& os = std::cout;
	os << "key:";
	ask_key(the_key);
	if(encry){
		os << "confirm key:";
		ask_key(tmp_key);

		if(! the_key.equal_to(tmp_key)){
			os << "key confirmation failed." << std::endl;

			the_key.clear(true, true);
			tmp_key.clear(true, true);
			return;
		}
	}
}

void
cry_encryptor::init_key(){
	std::ostream& os = std::cout;

	if(encry && ! has_input()){
		return;
	}
	if(! encry && ! has_target()){
		return;
	}

	if(key.is_empty()){
		get_key(key);
	}

	if(key.is_empty()){
		return;
	}
	CRY_CK(! key.is_empty());

	int min_sz = sizeof(unsigned long);
	if(key.size() < min_sz){
		os << "Minimum key size is " << min_sz << "." << std::endl;
		key.clear(true, true);
		key_bits.clear(true, true);
		key_longs.clear(true, true);
		CRY_CK(! has_key());
		return;
	}

	key.init_s_bit_row(key_bits);
	key_longs.init_data_with_s_bit_row(key_bits);
}

void
cry_encryptor::shake_key(tak_mak& tm){
	long nn = tm.gen_rand_int32_ie(MIN_KEY_INIT_CHANGES, MAX_KEY_INIT_CHANGES);

	for(long aa = 0; aa < nn; aa++){
		long idx1 = tm.gen_rand_int32_ie(0, key_bits.size());
		long idx2 = tm.gen_rand_int32_ie(0, key_bits.size());
		key_bits.swap(idx1, idx2);
	}
}

void
cry_encryptor::init_tak_maks(){
	std::ostream& os = std::cout;
	MARK_USED(os);
	if(! has_key()){
		return;
	}

	if(key_longs.size() == 1){
		os << "WARNING. Using MINIMUM key size !!!" << std::endl;
	}
	
	init_tak_mak_with_key(for_bytes_dest);	
	shake_key(for_bytes_dest);

	init_tak_mak_with_key(for_bits_dest);
	shake_key(for_bits_dest);

	init_tak_mak_with_key(for_bits_src);
	shake_key(for_bits_src);
}

void
cry_encryptor::init_target_encry(){
	if(! has_input()){
		return;
	}

	if(! has_key()){
		return;
	}

	//CRY_CK(has_input());
	std::ostream& os = std::cout;

	long hd_sz = 0;
	long tl_sz = 0;

	if(with_sha){ // INTERNAL SHA
		hd_sz = sizeof(long);
		tl_sz = NUM_BYTES_SHA2;
	}

	long cry_data_sz = 0;
	char* cry_data = NULL_PT;

	std::ifstream& in_stm = input_stm;

	cry_data = read_file(in_stm, cry_data_sz, hd_sz, tl_sz); 
	pt_file_data = cry_data;
	file_data_sz = cry_data_sz;

	if(cry_data == NULL_PT){
		os << "Could not read file " << input_file_nm << std::endl;
		return;
	}

	if(with_sha){
		unsigned char* pt_dat = NULL_PT;
		unsigned char* pt_sha = NULL_PT;

		pt_dat = (unsigned char*)(cry_data + hd_sz);
		pt_sha = (unsigned char*)(cry_data + cry_data_sz - tl_sz);

		long orig_file_sz = cry_data_sz - hd_sz - tl_sz;

		pt_as(cry_data, long) = orig_file_sz;
		sha2(pt_dat, orig_file_sz, pt_sha, 0); // INTERNAL SHA
	}

	target_bytes.init_data((t_1byte*)cry_data, cry_data_sz);
	target_bits.init_data((t_1byte*)cry_data, cry_data_sz);
}

void
cry_encryptor::init_target_decry(){
	if(! has_input()){
		return;
	}

	std::ostream& os = std::cout;

	unsigned char sha_arr[NUM_BYTES_SHA2];
	memset(sha_arr, 0, NUM_BYTES_SHA2);

	CRY_CK(pt_file_data == NULL_PT);
	CRY_CK(file_data_sz == 0);

	std::ifstream& in_stm = input_stm;

	pt_file_data = read_file(in_stm, file_data_sz); 

	if(pt_file_data == NULL_PT){
		os << "Could not read file " << input_file_nm << std::endl;
		return;
	}

	CRY_CK(cry_vr_msg != NULL_PT);
	CRY_CK(cry_vr_msg_sz != 0);

	if(file_data_sz > cry_vr_msg_sz){
		int cmp_hd = memcmp(pt_file_data, cry_vr_msg, cry_vr_msg_sz);
		if(with_sha && (cmp_hd != 0)){
			os << "File " << input_file_nm << " does not seem to be a " << std::endl;
			os << "-----------------------" << std::endl;
			os << cry_vr_msg << std::endl;
			os << "-----------------------" << std::endl;
			os << "file." << std::endl;
			os << std::endl;
			os << "If it is a raw encrypted file " 
				<< "(using the -r option), "
				<< " the -r option must be selected for " 
				<< "decryption too." << std::endl;
			os << std::endl;
			os << cry_help;
			end_target();
			return;
		}
		if(! with_sha && (cmp_hd == 0)){
			os << "File " << input_file_nm << " seems to be encrypted ";
			os << "without the -r (row) option." << std::endl;
			os << std::endl;
			os << "If you get a messy file try without it." 
				<< std::endl;
		}
	}

	long cry_data_sz = file_data_sz;
	unsigned char* cry_data = (unsigned char*)(pt_file_data);
	
	if(with_sha){
		
		s_row<t_1byte> tmp_hd;
		tmp_hd.init_data((t_1byte*)pt_file_data, file_data_sz);
		
		ch_string in_sha = "";
		long in_data_sz = 0;
		char* in_data = NULL_PT;
		get_info_header_decry(tmp_hd, in_sha, in_data, in_data_sz);
		
		if(in_data == NULL_PT){
			os << "Corrupt cry encrypted file " << input_file_nm << std::endl;
			end_target();
			return;
		}
		
		ch_string calc_sha = sha_txt_of_arr((uchar_t*)in_data, in_data_sz);
		if(calc_sha != in_sha){
			os << "Verification BEFORE decry failed with " 
				<< "cry encrypted file" << input_file_nm 
				<< std::endl;
			os << "File is corrupted." << std::endl;
			end_target();
			return;
		}

		cry_data_sz = in_data_sz;
		cry_data = (unsigned char*)(in_data);
	}

	target_bytes.init_data((t_1byte*)cry_data, cry_data_sz);
	target_bits.init_data((t_1byte*)cry_data, cry_data_sz);
}

void	
cry_encryptor::write_encry_file(const char* out_nm)
{
	std::ostream& os = std::cout;

	if(target_bytes.is_empty()){
		return;
	}

	std::ofstream out_stm;
	out_stm.open(out_nm, std::ios::binary);
	if(! out_stm.good() || ! out_stm.is_open()){
		os << "Archivo de salida " << out_nm << 
			" invalido." << std::endl;
		return;
	}
	t_dword pos = out_stm.tellp();
	MARK_USED(pos);
	CRY_CK(pos == 0);

	unsigned char* cry_data = (unsigned char*)target_bytes.get_data();
	long cry_data_sz = target_bytes.get_data_sz();
	
	if(with_sha){
		target_sha = sha_txt_of_arr((uchar_t*)target_bytes.get_data(), target_bytes.size());
		row<char> txt_hd;
		set_info_header_encry(txt_hd, target_sha, cry_data_sz);
		out_stm.write((const char*)txt_hd.get_data(), txt_hd.get_data_sz());
	}

	out_stm.write((const char*)cry_data, cry_data_sz);
	out_stm.close();
}

/*
void
cry_encryptor::init_target_decry(){
	if(! has_input()){
		return;
	}

	std::ostream& os = std::cout;

	unsigned char sha_arr[NUM_BYTES_SHA2];
	memset(sha_arr, 0, NUM_BYTES_SHA2);

	CRY_CK(pt_file_data == NULL_PT);
	CRY_CK(file_data_sz == 0);

	std::ifstream& in_stm = input_stm;

	pt_file_data = read_file(in_stm, file_data_sz); 

	if(pt_file_data == NULL_PT){
		os << "Could not read file " << input_file_nm << std::endl;
		return;
	}

	CRY_CK(cry_vr_msg != NULL_PT);
	CRY_CK(cry_vr_msg_sz != 0);

	if(file_data_sz > cry_vr_msg_sz){
		int cmp_hd = memcmp(pt_file_data, cry_vr_msg, cry_vr_msg_sz);
		if(with_sha && (cmp_hd != 0)){
			os << "File " << input_file_nm << " does not seem to be a " << std::endl;
			os << "-----------------------" << std::endl;
			os << cry_vr_msg << std::endl;
			os << "-----------------------" << std::endl;
			os << "file." << std::endl;
			os << std::endl;
			os << "If it is a raw encrypted file " 
				<< "(using the -r option), "
				<< " the -r option must be selected for " 
				<< "decryption too." << std::endl;
			os << std::endl;
			os << cry_help;
			end_target();
			return;
		}
		if(! with_sha && (cmp_hd == 0)){
			os << "File " << input_file_nm << " seems to be encrypted ";
			os << "without the -r (row) option." << std::endl;
			os << std::endl;
			os << "If you get a messy file try without it." 
				<< std::endl;
		}
	}

	long encry_hd_sz = 0; 
		
	if(with_sha){
		encry_hd_sz = cry_vr_msg_sz + sizeof(long);
	}

	if(file_data_sz < encry_hd_sz){
		os << "Not a cry formated file " << input_file_nm << std::endl;
		end_target();
		return;
	}

	long cry_data_sz = file_data_sz;
	unsigned char* cry_data = 
		(unsigned char*)(pt_file_data + encry_hd_sz);

	if(with_sha){
		cry_data_sz = pt_as((pt_file_data + cry_vr_msg_sz), long);

		long orig_cry_data_sz = file_data_sz - encry_hd_sz - NUM_BYTES_SHA2;
		if((orig_cry_data_sz < 0) || (cry_data_sz != orig_cry_data_sz)){
			os << "Corrupt cry encrypted file " << input_file_nm << std::endl;
			end_target();
			return;
		}

		unsigned char* cry_sha = sha_arr;
		sha2(cry_data, cry_data_sz, cry_sha, 0); // EXTERNAL SHA

		void* orig_cry_sha = cry_data + cry_data_sz;
		int cmp_val = memcmp(cry_sha, orig_cry_sha, NUM_BYTES_SHA2);
		if(cmp_val != 0){
			os << "Verification BEFORE decry failed with " 
				<< "cry encrypted file" << input_file_nm 
				<< std::endl;
			os << "File is corrupted." << std::endl;
			end_target();
			return;
		}
	}

	target_bytes.init_data((t_1byte*)cry_data, cry_data_sz);
	target_bits.init_data((t_1byte*)cry_data, cry_data_sz);
}

void	
cry_encryptor::write_encry_file(const char* out_nm)
{
	std::ostream& os = std::cout;

	if(target_bytes.is_empty()){
		return;
	}

	std::ofstream out_stm;
	out_stm.open(out_nm, std::ios::binary);
	if(! out_stm.good() || ! out_stm.is_open()){
		os << "Archivo de salida " << out_nm << 
			" invalido." << std::endl;
		return;
	}
	t_dword pos = out_stm.tellp();
	MARK_USED(pos);
	CRY_CK(pos == 0);

	unsigned char* cry_data = (unsigned char*)target_bytes.get_data();
	long cry_data_sz = target_bytes.size();

	unsigned char sha_arr[NUM_BYTES_SHA2];
	unsigned char* cry_sha = sha_arr;
	if(with_sha){
		memset(sha_arr, 0, NUM_BYTES_SHA2);

		sha2((unsigned char*)cry_data, cry_data_sz, cry_sha, 0); // EXTERNAL SHA

		out_stm.write(cry_vr_msg, cry_vr_msg_sz);
		wrt_val(out_stm, cry_data_sz);
	}

	out_stm.write((const char*)cry_data, cry_data_sz);

	if(with_sha){
		out_stm.write((const char*)cry_sha, NUM_BYTES_SHA2); // EXTERNAL SHA
	}
	out_stm.close();
}
*/

void	
cry_encryptor::write_decry_file(const char* out_nm)
{
	std::ostream& os = std::cout;

	if(target_bytes.is_empty()){
		return;
	}

	std::ofstream out_stm;
	out_stm.open(out_nm, std::ios::binary);
	if(! out_stm.good() || ! out_stm.is_open()){
		os << "Archivo de salida " << out_nm << 
			" invalido." << std::endl;
		return;
	}
	t_dword pos = out_stm.tellp();
	MARK_USED(pos);
	CRY_CK(pos == 0);

	unsigned char sha_arr[NUM_BYTES_SHA2];
	memset(sha_arr, 0, NUM_BYTES_SHA2);

	long hd_sz = 0;
	long tl_sz = 0;
	long cry_data_sz = target_bytes.size();

	if(with_sha){
		hd_sz = sizeof(long);
		tl_sz = NUM_BYTES_SHA2;
		cry_data_sz = target_bytes.size() - hd_sz - tl_sz;

		if(cry_data_sz < 0){
			os << "File " << input_file_nm << 
				" found corrupted AFTER decry" << std::endl;
			return;
		}
	}

	unsigned char* cry_data = (unsigned char*)(target_bytes.get_data() + hd_sz);

	if(with_sha){
		unsigned char* cry_sha = sha_arr;
		sha2((unsigned char*)cry_data, cry_data_sz, cry_sha, 0); // INTERNAL SHA

		void* orig_cry_sha = cry_data + cry_data_sz;
		int cmp_val = memcmp(cry_sha, orig_cry_sha, NUM_BYTES_SHA2);
		if(cmp_val != 0){
			os << "Verification failed AFTER decry of "
				<< input_file_nm << std::endl;
			os << "Wrong key or corrupted file." << std::endl;
			return;
		}
	}

	out_stm.write((const char*)cry_data, cry_data_sz);
	out_stm.close();
}

void
sha_bytes_of_arr(uchar_t* to_sha, long to_sha_sz, row<uchar_t>& the_sha){
	the_sha.clear();
	the_sha.fill(0, NUM_BYTES_SHA2);
	uchar_t* sha_arr = (uchar_t*)(the_sha.get_c_array());

	uchar_t* ck_arr1 = to_sha;
	MARK_USED(ck_arr1);

	sha2(to_sha, to_sha_sz, sha_arr, 0);
	TOOLS_CK(ck_arr1 == to_sha);
	TOOLS_CK((uchar_t*)(the_sha.get_c_array()) == sha_arr);
}

ch_string 
sha_txt_of_arr(uchar_t* to_sha, long to_sha_sz){
	row<uchar_t>	the_sha;
	sha_bytes_of_arr(to_sha, to_sha_sz, the_sha);
	ch_string sha_txt = the_sha.as_hex_str();
	return sha_txt;
}

void
cry_encryptor::print_sha(){
	init_input();
	
	std::ostream& os = std::cout;

	unsigned char sha_arr[NUM_BYTES_SHA2];
	memset(sha_arr, 0, NUM_BYTES_SHA2);

	CRY_CK(pt_file_data == NULL_PT);
	CRY_CK(file_data_sz == 0);

	std::ifstream& in_stm = input_stm;

	pt_file_data = read_file(in_stm, file_data_sz); 

	if(pt_file_data == NULL_PT){
		std::cerr << "Could not read file " << input_file_nm << std::endl;
		return;
	}

	//unsigned char* cry_sha = sha_arr;
	//sha2((unsigned char*)pt_file_data, file_data_sz, cry_sha, 0);

	ch_string sha_str1 = sha_txt_of_arr((unsigned char*)pt_file_data, file_data_sz);
	os << "SHA_256=" << sha_str1 << std::endl;
}

long parse_long(const char*& pt_in, long line) {
	long	val = 0;
	bool	neg = false;

	if(*pt_in == '-'){ neg = true; pt_in++; }
	else if(*pt_in == '+'){ pt_in++; }

	if(! isdigit(*pt_in)){
		std::cerr << "Could not parse long " << pt_in << std::endl;
		return 0;
		//throw parse_exception(pax_bad_int, (char)(*pt_in), line);
	}
	while(isdigit(*pt_in)){
		val = val*10 + (*pt_in - '0');
		pt_in++;
	}
	return (neg)?(-val):(val);
}

long parse_long_str(ch_string& in_str){
	long line = 0;
	const char* pt_in = in_str.c_str();
	long vv = parse_long(pt_in, line);
	return vv;
}

void	
cry_encryptor::get_args(int argc, char** argv)
{
	std::ostream& os = std::cout;
	MARK_USED(os);

	CRY_CK(cry_vr_msg == NULL_PT);
	CRY_CK(cry_vr_msg_sz == 0);

	cry_vr_msg = (char*)(cry_vr4_msg.c_str());
	cry_vr_msg_sz = cry_vr4_msg.size();

	for(long ii = 1; ii < argc; ii++){
		ch_string the_arg = argv[ii];
		if(strcmp(argv[ii], "-h") == 0){
			prt_help = true;
		} else if(strcmp(argv[ii], "-v") == 0){
			prt_version = true;
		} else if(strcmp(argv[ii], "-r") == 0){
			with_sha = false;
		} else if(strcmp(argv[ii], "-x") == 0){
			as_hex = true;
		} else if(strcmp(argv[ii], "-s") == 0){
			just_sha = true;
		} else if(strcmp(argv[ii], "-d") == 0){
			encry = false;
		} else if((strcmp(argv[ii], "-k") == 0) && ((ii + 1) < argc)){
			int kk_idx = ii + 1; 
			ii++;

			int arg_sz = strlen(argv[kk_idx]);
			s_row<char> tmp_str(argv[kk_idx], arg_sz);

			tmp_str.copy_to(key);
			tmp_str.clear();
			//os << "key=" << key << std::endl;

		} else if(input_file_nm.size() == 0){
			input_file_nm = argv[ii]; 
		}
	}
}

void
cry_encryptor_main(int argc, char** argv){
	std::ostream& os = std::cout;

	bool l_ok = (sizeof(long) == 8);
	if(! l_ok){
		os << "Build failure expecting sizeof(long) == 8)" << std::endl; 
		os << "But sizeof(long) = " << sizeof(long) << std::endl; 
		os << "Build again this software" << std::endl; 
		return;
	}
	
	cry_encryptor cry_engine;

	cry_engine.get_args(argc, argv);

	if(cry_engine.prt_help){
		os << cry_help << std::endl;
		//test_header(cry_engine);
		return;
	}
	if(cry_engine.just_sha){
		cry_engine.print_sha();
		return;
	}
	if(cry_engine.prt_version){
		os << cry_vr_msg << std::endl;
		return;
	}
	if(cry_engine.input_file_nm.size() == 0){
		os << cry_help << std::endl;
		os << cry_vr_msg << std::endl;
		return;
	}

	cry_engine.process_file();
}

int	main(int argc, char** argv){
	cry_encryptor_main(argc, argv);
	return 0;
}

// test_cry.txt -e
// test_cry.txt.encry -d

// win32
// CAPSLOCK([lExpression])

// lin
// ioctl()

/*
	AFTER encrypt
		byte[] hex_enc_dat = convert.bytes_to_hex_bytes(enc_dat);
		
	BEFORE decrypt
		byte[] enc_dat = convert.hex_bytes_to_bytes(hex_enc);

	public static byte[] bytes_to_hex_bytes(byte[] the_bytes) {
		assert (the_bytes != null);
		int hx_sz = the_bytes.length * 2;
		byte[] hx_bytes = new byte[hx_sz];
		for (int ii = 0; ii < the_bytes.length; ii++) {
			String hx_str = String.format("%02x", the_bytes[ii]);
			byte[] hx_val = hx_str.getBytes();
			assert (hx_val.length == 2);
			hx_bytes[ii * 2] = hx_val[0];
			hx_bytes[(ii * 2) + 1] = hx_val[1];
		}
		return hx_bytes;
	}

	public static byte[] hex_bytes_to_bytes(byte[] the_hx_bytes) {
		assert (the_hx_bytes != null);
		if ((the_hx_bytes.length % 2) != 0) {
			throw new bad_emetcode(2, L.invalid_length);
		}
		int bytes_sz = the_hx_bytes.length / 2;
		byte[] the_bytes = new byte[bytes_sz];
		for (int ii = 0; ii < the_bytes.length; ii++) {
			byte b1 = the_hx_bytes[ii * 2];
			byte b2 = the_hx_bytes[(ii * 2) + 1];
			the_bytes[ii] = calc_val_byte(b1, b2);
		}
		return the_bytes;
	}



*/

void copy_string_in_arr(ch_string& src, row<char>& dest, row_index dest_beg_ii = 0){ 
	for(row_index aa = 0; aa < (row_index)src.size(); aa++){
		dest[dest_beg_ii + aa] = src[aa];
	}
}

row<char>&	operator << (row<char>& rr, ch_string& src){
	for(row_index aa = 0; aa < (row_index)src.size(); aa++){
		rr.push(src[aa]);
	}
	return rr;
}

row<char>&	operator << (row<char>& rr, const char* str){
	int aa = 0;
	while(str[aa] != '\0'){
		rr.push(str[aa]);
		aa++;
	}
	return rr;
}

ch_string
long_to_str(long val){
	bj_ostr_stream ss_val;
	ss_val << val;
	return ss_val.str();
}


void 
cry_encryptor::set_info_header_encry(row<char>& txt_hd, ch_string& data_sha, long data_size){
	txt_hd.clear();
	
	ch_string dat_sz_str = long_to_str(data_size);
	
	txt_hd << cry_vr4_msg;
	txt_hd << "\n";
	txt_hd << data_sha_field;
	txt_hd << data_sha;
	txt_hd << "\n";
	txt_hd << data_size_field;
	txt_hd << dat_sz_str;
	txt_hd << "\n";
	txt_hd << end_header;
}

void 
cry_encryptor::get_info_header_decry(s_row<t_1byte>& tgt, ch_string& data_sha, char*& pt_data, long& data_sz){
	const char* all_data = tgt.get_data();
	char* pt_rest_data = (char*)all_data;
	long rest_data_sz = tgt.get_data_sz();
	long rd_data_sz = 0;

	pt_data = NULL_PT;
	data_sz = 0;
	
	while(true){
		ch_string ln = read_arr_line(pt_rest_data, rest_data_sz);
		//std::cout << "LINE=" << ln << std::endl;
		if(ln.size() == 0){
			break;
		}
		if(ln.starts_with(data_sha_field)){
			data_sha = ln.substr(data_sha_field.size());
			data_sha.pop_back();
			//std::cout << "FOUND data_sha_field=" << data_sha << std::endl;
		}
		if(ln.starts_with(data_size_field)){
			ch_string val2 = ln.substr(data_size_field.size());
			val2.pop_back();
			rd_data_sz = parse_long_str(val2);
			//std::cout << "FOUND data_size_field=" << val2 << std::endl;
		}
		if(ln == end_header){
			//std::cout << "FOUND_END_HEADER" << std::endl;
			break;
		}
	}
	if(rd_data_sz != rest_data_sz){
		std::cerr << "Corrupted file. Header field " << data_size_field << " does not match actual size" << std::endl;
		pt_data = NULL_PT;
		data_sz = 0;
		return;
	}
	data_sz = rd_data_sz;
	pt_data = pt_rest_data;
}

void 
test_header(cry_encryptor& cry_engine){
	std::ostream& os = std::cout;
	row<char> txt_hd;
	ch_string the_sha = "ESTE_ES_EL_SHA";
	long the_sz = 123455876;
	cry_engine.set_info_header_encry(txt_hd, the_sha, the_sz);

	std::cout << "NEW_SZ =" << txt_hd.size() << std::endl;
	std::cout << "HD=\n" << txt_hd.get_c_array() << std::endl;
	
	s_row<t_1byte> tgt;
	tgt.init_data((t_1byte*)txt_hd.get_data(), txt_hd.get_data_sz());

	ch_string in_sha = "";
	char* in_data = NULL_PT;
	long in_sz = 0;
	cry_engine.get_info_header_decry(tgt, in_sha, in_data, in_sz);
	os << "in_sha=" << in_sha << std::endl; 
	os << "in_sz=" << in_sz << std::endl; 
}
