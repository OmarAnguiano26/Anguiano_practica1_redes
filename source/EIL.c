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
#include "myssn_aes.h"
#include "myssn_crc.h"

#include <stdio.h>


char tcpecho_app_data_print[64] = {0};
char tcpecho_app_data[64] = {0};

void EIL_InitCRC32()
{
	myssn_InitCrc32();
}

struct AES_ctx EIL_Init_AES()
{
	struct AES_ctx ctx;
	ctx = myssn_AES_Init();
	return ctx;
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
			chksum = myssn_CRC32(tcpecho_app_data, strlen(tcpecho_app_data));

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
			data_decrypted =  myssn_Decrypt(ctx,data_recived);
			PRINTF("Data after decrypt: %s\r\n",data_decrypted.padded_data);
			memcpy(data_buff,data_decrypted.padded_data,(len + 4));
			break;
		}
  	 
		return err;
	}
	return err;
}

err_t EIL_send(struct netconn *conn, struct AES_ctx ctx, uint8_t *data)
{
	AES_struct_data data_encrypt;
	uint32_t crc_result;
	uint8_t *crc_str;
	uint32_t size;
	err_t err;
	uint32_t len;
	uint8_t data_response[30] = "Hola Mundo";

	myssn_InitCrc32(); /**Call again to clean crc*/

	data_encrypt = myssn_Encrypt(ctx, data);

	/**CRC*/
	crc_result = myssn_CRC32(data_encrypt.padded_data, data_encrypt.pad_len);
	PRINTF("CRC: %d\r\n",crc_result);

	/***Attach CRC to data*/
	crc_str = (char *)&crc_result; /**Converts int to string so it can be sent over TCP*/
	for(int i = 0; i < 4; i++)
	{
		data_encrypt.padded_data[(data_encrypt.pad_len + i)] = crc_str[i];
	}

	PRINTF("Data after encrypt: %s\r\n",data_encrypt.padded_data);
	err = netconn_write(conn, data_encrypt.padded_data, (data_encrypt.pad_len + 4), NETCONN_COPY);

	return err;
}
