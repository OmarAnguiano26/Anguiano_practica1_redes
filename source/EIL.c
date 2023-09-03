/*
 * EIL.c
 *Encryption and Integrity Layer
 *  Created on: Sep 2, 2023
 *      Author: Omar_PC
 */

#include <aes.h>
#include "fsl_crc.h"
#include "EIL.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"


/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
void EIL_InitCrc32()
{
    crc_config_t config;
    CRC_Type *base = CRC0;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = 0xFFFFFFFFU;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

uint32_t EIL_CRC32(uint8_t *data, uint8_t len)
{
	CRC_Type *base = CRC0;
	uint32_t checksum32;

    CRC_WriteData(base, (uint8_t *)&data[0], len);
    checksum32 = CRC_Get32bitResult(base);

    //PRINTF("CRC-32: 0x%08x\r\n", checksum32);

    return checksum32;
}

struct AES_ctx EIL_AES_Init()
{
	/* AES data */
	uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);

	return ctx;
}

AES_struct_data EIL_Encrypt(struct AES_ctx ctx, uint8_t *data)
{
	size_t string_len, padded_len;
	uint8_t padded_msg[512] = {0};
	AES_struct_data AES_data;

	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
	string_len = strlen(data);
	//PRINTF("String length: %d\r\n", string_len);
	padded_len = string_len + (16 - (string_len%16) );
	memcpy(padded_msg, data, string_len);
	//PRINTF("String length padded: %d\r\n", padded_len);

	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);
	memcpy(AES_data.padded_data,padded_msg,padded_len);
	AES_data.len = string_len;
	AES_data.pad_len = padded_len;

	return AES_data;
}

AES_struct_data EIL_Decrypt(struct AES_ctx ctx,AES_struct_data Encrypted_msg)
{
	AES_CBC_decrypt_buffer(&ctx, Encrypted_msg.padded_data, Encrypted_msg.pad_len);
	return Encrypted_msg;
}
