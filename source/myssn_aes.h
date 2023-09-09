/*
 * myssn_aes.h
 *
 *  Created on: Sep 9, 2023
 *      Author: Omar_PC
 */

#ifndef MYSSN_AES_H_
#define MYSSN_AES_H_
#include <stdint.h>

typedef struct
{
	uint8_t padded_data[256]; /**Data to encrypt*/
	uint32_t len; /**length of the original data BEFORE padding*/
	uint32_t pad_len; /**length of data AFTER padding*/
}AES_struct_data;

/**Function to initialize AES module
 *
 *return: returns ctx so it can be used on encrypt decrypt functions
 * */
struct AES_ctx myssn_AES_Init();

/**Encryption function, this function encrypts the data
 * Data size must be a multiple of 16 so 0s are added to the array
 * params[]:
 * ctx: Variable from AES init
 * data: Array to encrypt
 *
 * return: Returns a structure with the encrypted data and length
 * */
AES_struct_data myssn_Encrypt(struct AES_ctx ctx, uint8_t *data);

/**Desencryption function, this function desencrypts the data
 * params[]:
 * ctx: Variable from AES init
 * Encrypted_msg: struct that contains the data to desencrypt and the size
 *
 * return: Returns a structure with the desencrypted data and length
 * */
AES_struct_data myssn_Decrypt(struct AES_ctx ctx,AES_struct_data Encrypted_msg);

#endif /* MYSSN_AES_H_ */
