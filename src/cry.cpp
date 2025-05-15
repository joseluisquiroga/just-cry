

/*************************************************************

cry.cpp
(C 2009) QUIROGA BELTRAN, Jose Luis. Bogotá - Colombia.

cry encryptor functions. no-trace style encryptor.

--------------------------------------------------------------*/

#include "cry.h"
#include "sha2.h"

DEFINE_MEM_STATS;

char* cry_vr_msg = NULL_PT;
long cry_vr_msg_sz = 0; 

std::string cry_vr2_msg =
"cry-encryptor v2.5\n"
"https://github.com/joseluisquiroga/just-cry\n"
"(c) 2025. QUIROGA BELTRAN, Jose Luis. Bogota - Colombia.\n"
;

std::string cry_help =
"cry <file_name> [-e|-d|-h|-v] [-x][-r]\n"
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

std::string cry_info = "cry_use.txt";

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

	long mem_sz = (data_sz + 1) * sizeof(char);
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
cry_encryptor::init_tak_maks(){
	std::ostream& os = std::cout;
	MARK_USED(os);
	if(! has_key()){
		return;
	}

	if(key_longs.size() == 1){
		os << "WARNING. Using MINIMUM key size !!!" << std::endl;
	}
	
	if(key_longs.size() == 1){
		for_bytes.init_with_long(key_longs[0]);
	} else {
		for_bytes.init_with_array(
				key_longs.get_c_array(), 
				key_longs.get_c_array_sz()
		);
	}

	long nn = for_bytes.gen_rand_int32_ie(
			MIN_KEY_INIT_CHANGES, MAX_KEY_INIT_CHANGES);

	for(long aa = 0; aa < nn; aa++){
		long idx1 = for_bytes.gen_rand_int32_ie(
						0, key_bits.size());
		long idx2 = for_bytes.gen_rand_int32_ie(
						0, key_bits.size());

		key_bits.swap(idx1, idx2);
	}

	if(key_longs.size() == 1){
		for_bits.init_with_long(key_longs[0]);
	} else {
		for_bits.init_with_array(
				key_longs.get_c_array(), 
				key_longs.get_c_array_sz()
		);
	}
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

	if(with_sha){
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
		sha2(pt_dat, orig_file_sz, pt_sha, 0);
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
		sha2(cry_data, cry_data_sz, cry_sha, 0);

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

		sha2((unsigned char*)cry_data, cry_data_sz, cry_sha, 0);

		out_stm.write(cry_vr_msg, cry_vr_msg_sz);
		wrt_val(out_stm, cry_data_sz);
	}

	out_stm.write((const char*)cry_data, cry_data_sz);

	if(with_sha){
		out_stm.write((const char*)cry_sha, NUM_BYTES_SHA2);
	}
	out_stm.close();
}

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
		sha2((unsigned char*)cry_data, cry_data_sz, cry_sha, 0);

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
cry_encryptor::get_args(int argc, char** argv)
{
	std::ostream& os = std::cout;
	MARK_USED(os);

	CRY_CK(cry_vr_msg == NULL_PT);
	CRY_CK(cry_vr_msg_sz == 0);

	cry_vr_msg = (char*)(cry_vr2_msg.c_str());
	cry_vr_msg_sz = cry_vr2_msg.size();

	for(long ii = 1; ii < argc; ii++){
		std::string the_arg = argv[ii];
		if(strcmp(argv[ii], "-h") == 0){
			prt_help = true;
		} else if(strcmp(argv[ii], "-v") == 0){
			prt_version = true;
		} else if(strcmp(argv[ii], "-r") == 0){
			with_sha = false;
		} else if(strcmp(argv[ii], "-x") == 0){
			as_hex = true;
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
	cry_encryptor cry_engine;

	cry_engine.get_args(argc, argv);

	if(cry_engine.prt_help){
		os << cry_help << std::endl;
		os << "sizeof(long) = " << sizeof(long) << std::endl;
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