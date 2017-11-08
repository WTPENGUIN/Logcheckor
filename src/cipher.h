#pragma once
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
#define LENGTH_TEXT 8
#define LENGTH_ROUND_PART_TEXT 4
#define LENGTH_KEY 4
#define MAX_ROUND 14

class CipherKey {
public:
	CipherKey();
	virtual ~CipherKey() ;

	char *get_defaultkey();
	char *get_decryptkey(char *encrypt_key);
	char *get_cipherkey(bool flag);

	void shift_right_key();
	void shift_left_key();

	void setkey(char *inputkey);

private:
	char key[LENGTH_KEY + 1];
	char decrypt_key[LENGTH_KEY + 1];
};

class Encryption : public CipherKey {
public:
	Encryption();
	~Encryption();

	char* encryption_process(char *text, char *key = NULL);
	char* decryption_process(char *text, char *key = NULL);
	char* round(char *text, bool flag);

	void file_encrypt(char *input, char *output, char *key = NULL);
	void file_decrypt(char *input, char *output, char *key = NULL);

private:
	char result_phase[LENGTH_TEXT + 1];
	bool flag_setting_key;
};
