/*
 * myssn_aes.c
 *
 *  Created on: Sep 9, 2023
 *      Author: Omar_PC
 */
#include "myssn_aes.h"
#include <aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct AES_ctx myssn_AES_Init()
{
	/* AES data */
	uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);

	return ctx;
}

AES_struct_data myssn_Encrypt(struct AES_ctx ctx, uint8_t *data)
{
	size_t string_len, padded_len;
	uint8_t padded_msg[256] = {0};
	AES_struct_data AES_data;

	/* To encrypt an array its length must be a multiple of 16 so we add zeros */
	string_len = strlen(data);

	padded_len = string_len + (16 - (string_len%16) );
	memcpy(padded_msg, data, string_len);

	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);
	/**Copies encrypted data and size to the EIL struct*/
	//AES_data.padded_data = padded_msg;
	memcpy(AES_data.padded_data,padded_msg,padded_len);
	AES_data.len = string_len;
	AES_data.pad_len = padded_len;

	return AES_data;
}

AES_struct_data myssn_Decrypt(struct AES_ctx ctx,AES_struct_data Encrypted_msg)
{
	AES_CBC_decrypt_buffer(&ctx, Encrypted_msg.padded_data, Encrypted_msg.pad_len);
	return Encrypted_msg;
}

