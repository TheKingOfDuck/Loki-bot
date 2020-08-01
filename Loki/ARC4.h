/*
 * ARC4.h
 *
 *  Created on: Apr 6, 2016
 *      Author: fabio
 */
#ifndef ARC4_H_
#define ARC4_H_

 /**
 * RC4 Encryptor utility for decrypting Strings
 * @brief Utility to RC4 encrypt bytes
 */
class ARC4 {
public:
	/**
	* Set/Reset the key use this method if you want to reuse the same ARC4 structure again
	* @param k the key
	* @param size the size of the key
	*/
	void setKey(unsigned char * k, int size);
	/**
	* Encrypts a string
	* @param in String to encrypt
	* @param out String to decrypt
	* @param size size of the key to encrypt
	*/
	void encrypt(unsigned char * in, unsigned char * out, int size);
	/**
	* Encrypts a string
	* @param in String to encrypt
	* @param out String to decrypt
	* @param size size of the key to encrypt
	*/
	void encrypt(char * in, char * out, int size);
	ARC4();
protected:
	void ksa(unsigned char * key);
	void swap(unsigned char data[], int i, int j);
	void prga(unsigned char * plaintext, unsigned char * cipher, int size);
	void prga(char * plaintext, char * cipher, int size);
	unsigned char sbox[256];
	int sizeKey, prgaIndexA, prgaIndexB;
};



#endif /* ARC4_H_ */