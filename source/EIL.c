/*
 * EIL.c
 *Encryption and Integrity Layer
 *  Created on: Sep 2, 2023
 *      Author: Omar_PC
 */

#include "lwip/sys.h"
#include "lwip/api.h"
#include "tcpecho.h"
#include "lwip/opt.h"

#include <aes.h>
#include "fsl_crc.h"
#include "EIL.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>     /* atoi */


char tcpecho_app_data_print[64] = {0};
char tcpecho_app_data[64] = {0};

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

AES_struct_data EIL_Decrypt(struct AES_ctx ctx,AES_struct_data Encrypted_msg)
{
	AES_CBC_decrypt_buffer(&ctx, Encrypted_msg.padded_data, Encrypted_msg.pad_len);
	return Encrypted_msg;
}

err_t EIL_receive(struct netconn *conn, struct AES_ctx ctx, uint8_t *data_buff)
{
	struct netbuf *buf;
	err_t err;
	void *data;
	u16_t len;
	uint32_t chksum;
	uint32_t ucrc_received = 0;
	uint8_t scrc_received[4];
	uint8_t srcr_swapped[4];
	uint32_t crc_flag;

	uint32_t crc_result;
	uint8_t crc_send[10];


	AES_struct_data data_recived;
	AES_struct_data data_decrypted, data_encrypt;
	PRINTF("Start of receive\r\n");

	while (1)
	{
		/*printf("Recved\n");*/
		err = netconn_recv(conn, &buf);
		if(err == ERR_OK)
		{
			netbuf_data(buf, &data, &len);
			/**Separates CRC from data data*/
			memcpy(tcpecho_app_data_print, data, len);
			netbuf_delete(buf); /**Deletes data*/

			/**Splits CRC on another string*/
			for(int i = 0; i <= 4; i++)
			{
				scrc_received[3 - i] = tcpecho_app_data_print[(len - 1) - i];
			}

			for(int i = 0; i < (len - 4); i++)
			{
				tcpecho_app_data[i] = tcpecho_app_data_print[i];
			}
			/**Calculates CRC*/
			chksum = EIL_CRC32(tcpecho_app_data, strlen(tcpecho_app_data));

			/**Converts the crc string to uint*/
			memcpy(&ucrc_received, scrc_received,4);

            /**Compare CRC*/
			PRINTF("CRC received = %d\r\n",ucrc_received);
            if(ucrc_received == chksum)
            {
            	PRINTF("CRC Correct\r\n");
            }

			/**Decrypts*/
			memcpy(data_recived.padded_data, tcpecho_app_data, strlen(tcpecho_app_data));
			data_recived.pad_len = len - 4;//strlen(tcpecho_app_data);
			data_decrypted =  EIL_Decrypt(ctx,data_recived);
			PRINTF("Data after decrypt: %s\r\n",data_decrypted.padded_data);
			memcpy(data_buff,data_decrypted.padded_data,strlen(data_decrypted.padded_data));
			break;
		}
  	 
		return err;
	}
	return err;
}

err_t EIL_send(struct netconn *conn, struct AES_ctx ctx)
{
	AES_struct_data data_encrypt;
	uint32_t crc_result;
	uint8_t *crc_str;
	uint32_t size;
	err_t err;
	uint32_t len;
	uint8_t data_response[30] = "Hola Mundo";

	EIL_InitCrc32(); /**Call again to clean crc*/

	data_encrypt = EIL_Encrypt(ctx, data_response);

	/**CRC*/
	crc_result = EIL_CRC32(data_encrypt.padded_data, data_encrypt.pad_len);
	PRINTF("CRC: %d\r\n",crc_result);

	/***Attach CRC to data*/
	crc_str = (char *)&crc_result; /**Converts int to string so it can be sent over TCP*/
	for(int i = 0; i < 4; i++)
	{
		data_encrypt.padded_data[(data_encrypt.pad_len + i)] = crc_str[i];
	}
	//data_encrypt.padded_data[data_encrypt.pad_len] = *crc_str; /**Concats CRC string to the data before sending*/

	PRINTF("Data after encrypt: %s\r\n",data_encrypt.padded_data);
	len = strlen(data_encrypt.padded_data);
	uint8_t *data;
//	uint8_t data[30] = {0};
//	for(int i = 0; i < len; i++)
//	{
//		data[i] = data_encrypt.padded_data[i];
//	}
	//memcpy(data,data_encrypt.padded_data,len);
	err = netconn_write(conn, data_encrypt.padded_data, (data_encrypt.pad_len + 4), NETCONN_COPY);

	return err;
}
