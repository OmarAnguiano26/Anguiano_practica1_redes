/*
 * EIL.h
 *Encryption and Integrity Layer
 *  Created on: Sep 2, 2023
 *      Author: Omar_PC
 */

#ifndef EIL_H_
#define EIL_H_

typedef struct
{
	uint8_t padded_data[256]; /**Data to encrypt*/
	uint32_t len; /**length of the original data BEFORE padding*/
	uint32_t pad_len; /**length of data AFTER padding*/
	/**TODO Length diff will be used to eliminate padding*/
}AES_struct_data;

/**This function Init CRC32 before calling it
 * Used a default seed of 0xFFFFFFF*/
void EIL_InitCrc32();

/** This function performs checksum32 on data
 * params[]:
 * data: Array to perform checksum
 * len: length of the array
 *
 * return: Returns the value of checksum
 * */
uint32_t EIL_CRC32(uint8_t *data, uint8_t len);

/**Function to initialize AES module
 *
 *return: returns ctx so it can be used on encrypt decrypt functions
 * */
struct AES_ctx EIL_AES_Init();

/**Encryption function, this function encrypts the data
 * Data size must be a multiple of 16 so 0s are added to the array
 * params[]:
 * ctx: Variable from AES init
 * data: Array to encrypt
 *
 * return: Returns a structure with the encrypted data and length
 * */
AES_struct_data EIL_Encrypt(struct AES_ctx ctx, uint8_t *data);

/**Desencryption function, this function desencrypts the data
 * params[]:
 * ctx: Variable from AES init
 * Encrypted_msg: struct that contains the data to desencrypt and the size
 *
 * return: Returns a structure with the desencrypted data and length
 * */
AES_struct_data EIL_Decrypt(struct AES_ctx ctx,AES_struct_data Encrypted_msg);


#endif /* EIL_H_ */
