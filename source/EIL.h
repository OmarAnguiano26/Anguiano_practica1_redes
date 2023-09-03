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
	uint8_t padded_data[512];
	uint32_t len;
	uint32_t pad_len;
}AES_struct_data;

void EIL_InitCrc32();
uint32_t EIL_CRC32(uint8_t *data, uint8_t len);
struct AES_ctx EIL_AES_Init();
AES_struct_data EIL_Encrypt(struct AES_ctx ctx, uint8_t *data);
AES_struct_data EIL_Decrypt(struct AES_ctx ctx,AES_struct_data Encrypted_msg);


#endif /* EIL_H_ */
