#include "cipher.h"
CipherKey::CipherKey()
{
	for (int index = 0; index < LENGTH_KEY; index++) {
		key[index] = 'A' + rand() % 24;
		decrypt_key[index] = '\0';
	}
	key[LENGTH_KEY] = '\0';
	decrypt_key[LENGTH_KEY] = '\0';
}

CipherKey::~CipherKey()
{
	for (int destroy = 0; destroy < LENGTH_KEY; destroy++) {
		key[destroy] = '\0';
	}
}

char* CipherKey::get_defaultkey()
{
	return key;
}

char* CipherKey::get_decryptkey(char *encrypt_key) {
	for (int index = 0; index < LENGTH_KEY; index++) {
		decrypt_key[index] = *(encrypt_key + index);
	}
	decrypt_key[LENGTH_KEY] = '\0';

	char overwrite = decrypt_key[0];
	char bit_overflow = 0;
	char before_write = 0;

	for (int index_round = 0; index_round < MAX_ROUND; index_round++) {
		overwrite = decrypt_key[0];
		bit_overflow = 0;
		before_write = 0;

		for (int index_key = 0; index_key < LENGTH_KEY; index_key++) {
			before_write = decrypt_key[index_key];
			decrypt_key[index_key] = overwrite;
			if (bit_overflow == 1) {
				decrypt_key[index_key] = decrypt_key[index_key] | 0x40;
			}
			bit_overflow = before_write & 0x01;
			overwrite = before_write >> 1;
		}
		decrypt_key[0] = overwrite;
		if (bit_overflow == 1) {
			decrypt_key[0] = decrypt_key[0] | 0x40;
		}
		decrypt_key[LENGTH_KEY] = '\0';
	}

	return decrypt_key;
}

char* CipherKey::get_cipherkey(bool flag)
{
	if (flag == true) {
		shift_right_key();
	}
	else {
		shift_left_key();
	}
	return key;
}

void CipherKey::shift_right_key()
{
	char overwrite = key[0];
	char bit_overflow = 0;
	char before_write = 0;


	for (int index_key = 0; index_key < LENGTH_KEY; index_key++) {
		before_write = key[index_key];
		key[index_key] = overwrite;
		if (bit_overflow == 1) {
			key[index_key] = key[index_key] | 0x40;
		}
		bit_overflow = before_write & 0x01;
		overwrite = before_write >> 1;
	}
	key[0] = overwrite;
	if (bit_overflow == 1) {
		key[0] = key[0] | 0x40;
	}
	key[LENGTH_KEY] = '\0';
}

void CipherKey::shift_left_key()
{
	char overwrite = key[LENGTH_KEY - 1];
	char bit_overflow = 0;
	char before_write = 0;

	for (int index_key = LENGTH_KEY - 1; index_key > -1; index_key--) {
		before_write = key[index_key];
		key[index_key] = overwrite;
		if (bit_overflow == 64) {
			key[index_key] = key[index_key] | 0x01;
		}
		bit_overflow = before_write & 0x40;
		overwrite = before_write << 1;
		overwrite &= 0x7F;
	}
	key[LENGTH_KEY - 1] = overwrite;
	if (bit_overflow == 64) {
		key[LENGTH_KEY - 1] = key[LENGTH_KEY - 1] | 0x01;
	}
	key[LENGTH_KEY] = '\0';
}

void CipherKey::setkey(char *inputkey)
{
	for (int index_key = 0; index_key < LENGTH_KEY; index_key++) {
		key[index_key] = *(inputkey + index_key);
	}
	key[LENGTH_KEY] = '\0';
}

Encryption::Encryption()
{
	flag_setting_key = false;
}

Encryption::~Encryption()
{
	flag_setting_key = false;
}

char* Encryption::encryption_process(char *text, char *key) {
	char repo[LENGTH_TEXT + 1];
	if (key != NULL) {
		flag_setting_key = true;
		setkey(key);
	}
	for (int index_round = 0; index_round < MAX_ROUND; index_round++) {
		text = round(text, true);
		for (int copy = 0; copy < LENGTH_TEXT; copy++) {
			repo[copy] = *(text + copy);
		}
		repo[LENGTH_TEXT] = '\0';
		text = repo;
	}

	return text;
}

char* Encryption::decryption_process(char *text, char *key) {
	char repo[LENGTH_TEXT + 1];
	if (key != NULL) {
		flag_setting_key = true;
		setkey(key);
	}
	shift_right_key();
	for (int index_round = 0; index_round < MAX_ROUND; index_round++) {
		text = round(text, false);
		for (int copy = 0; copy < LENGTH_TEXT; copy++) {
			repo[copy] = *(text + copy);
		}
		repo[LENGTH_TEXT] = '\0';
		text = repo;
	}

	return text;
}

char* Encryption::round(char *text, bool flag) {
	char part_left[LENGTH_ROUND_PART_TEXT], part_right[LENGTH_ROUND_PART_TEXT];
	char *roundkey;
	roundkey = get_cipherkey(flag);

	for (int copy = 0; copy < LENGTH_ROUND_PART_TEXT; copy++) {
		part_left[copy] = *(text + copy);
	}
	for (int copy = LENGTH_ROUND_PART_TEXT; copy < LENGTH_TEXT; copy++) {
		part_right[copy - LENGTH_ROUND_PART_TEXT] = *(text + copy);
	}


	if (flag == true) {
		for (int oper = 0; oper < LENGTH_ROUND_PART_TEXT; oper++) {
			part_left[oper] = part_left[oper] ^ (*(roundkey + oper));
		}
	}
	else {
		for (int oper = 0; oper < LENGTH_ROUND_PART_TEXT; oper++) {
			part_right[oper] = part_right[oper] ^ (*(roundkey + oper));
		}
	}

	for (int change = 0; change < LENGTH_ROUND_PART_TEXT; change++) {
		char temp = part_right[change];
		part_right[change] = part_left[change];
		part_left[change] = temp;
	}

	for (int copy = 0; copy < LENGTH_ROUND_PART_TEXT; copy++) {
		result_phase[copy] = part_left[copy];
	}
	for (int copy = LENGTH_ROUND_PART_TEXT; copy < LENGTH_TEXT; copy++) {
		result_phase[copy] = part_right[copy - LENGTH_ROUND_PART_TEXT];
	}

	result_phase[LENGTH_TEXT] = '\0';
	return result_phase;
}

void Encryption::file_encrypt(char *input, char *output, char *key)
{
	Encryption encrypt_file;
	ifstream file_reading;
	ofstream file_writing;
	int length, count;
	int index_start = 0;
	char readchar_buffer[9];
	char writechar_buffer[9];
	char *buffer_string;

	file_reading.open(input, ios::binary);
	if (!file_reading.is_open()) {
		return;
	}
	file_reading.seekg(0, ios::end);
	length = file_reading.tellg();
	file_reading.seekg(0, ios::beg);
	file_writing.open(output, ios::binary);

	char *buffer = new char[length];
	count = (int)(length / 8);
	writechar_buffer[8] = '\0';
	readchar_buffer[8] = '\0';

	file_reading.read(buffer, length);

	for (int loop = count; count > -1; count--) {
		for (int copy = 0; copy < 8; copy++) {
			readchar_buffer[copy] = buffer[index_start + copy];
		}
		buffer_string = encrypt_file.encryption_process(readchar_buffer, key);
		for (int copy = 0; copy < 8; copy++) {
			writechar_buffer[copy] = *(buffer_string + copy);
		}
		for (int copy = 0; copy < 8; copy++) {
			buffer[index_start + copy] = writechar_buffer[copy];
		}
		index_start += 8;
	}

	file_writing.write(buffer, length);
	file_reading.close();
	file_writing.close();
	return;
}

void Encryption::file_decrypt(char *input, char *output, char *key)
{
	Encryption decrypt_file;
	ifstream file_reading;
	ofstream file_writing;
	int length, count;
	int index_start = 0;
	char readchar_buffer[9];
	char writechar_buffer[9];
	char *buffer_string;

	file_reading.open(input, ios::binary);
	if (!file_reading.is_open()) {
		return;
	}
	file_reading.seekg(0, ios::end);
	length = file_reading.tellg();
	file_reading.seekg(0, ios::beg);
	file_writing.open(output, ios::binary);

	char *buffer = new char[length];
	count = (int)(length / 8);
	readchar_buffer[8] = '\0';
	writechar_buffer[8] = '\0';
	file_reading.read(buffer, length);

	for (int loop = count; count > -1; count--) {
		for (int copy = 0; copy < 8; copy++) {
			readchar_buffer[copy] = buffer[index_start + copy];
		}
		buffer_string = decrypt_file.decryption_process(readchar_buffer, key);
		for (int copy = 0; copy < 8; copy++) {
			writechar_buffer[copy] = *(buffer_string + copy);
		}
		for (int copy = 0; copy < 8; copy++) {
			buffer[index_start + copy] = writechar_buffer[copy];
		}
		index_start += 8;
	}

	file_writing.write(buffer, length);

	file_reading.close();
	file_writing.close();

	return;
}