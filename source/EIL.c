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
	u16_t len; /**Length of received data*/

	uint32_t chksum; /**Stores CRC calculated from received data*/
	uint32_t ucrc_received = 0; /**Stores CRC received from client*/
	uint8_t scrc_received[4]; /**Stores CRC result as string*/

	AES_struct_data data_recived;
	AES_struct_data data_decrypted;
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
			netbuf_delete(buf); /**Deletes buffer to free space*/

			/**Splits CRC on another string*/
			for(int i = 0; i <= CRC_LENGTH; i++)
			{
				/**Copies the last 4 bytes from the data received to extract CRC*/
				scrc_received[(CRC_LENGTH - 1) - i] = tcpecho_app_data_print[(len - 1) - i];
			}
			/**Copies the received data to another string but without CRC*/
			for(int i = 0; i < (len - CRC_LENGTH); i++)
			{
				tcpecho_app_data[i] = tcpecho_app_data_print[i];
			}
			/**Calculates CRC*/
			chksum = myssn_CRC32(tcpecho_app_data, (len - CRC_LENGTH));

			/**Converts calculated CRC to uint*/
			memcpy(&ucrc_received, scrc_received,CRC_LENGTH);

            /**Compares CRC received from the calculated with data*/
			PRINTF("CRC received = %u\r\n",ucrc_received);
            if(ucrc_received == chksum)
            {
            	PRINTF("CRC Correct\r\n");
            }

			/**Decrypts*/
            /**Copies data string to the struct*/
			memcpy(data_recived.padded_data, tcpecho_app_data, (len - CRC_LENGTH));
			data_recived.pad_len = len - CRC_LENGTH;
			data_decrypted =  myssn_Decrypt(ctx,data_recived);
			PRINTF("Data after decrypt: %s\r\n",data_decrypted.padded_data);
			/**Copies the encrypted data to string so it can be value can be returned outside*/
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
	err_t err;

	/**Call again to clean previous CRC*/
	myssn_InitCrc32();
	/**Encrypts echo data*/
	data_encrypt = myssn_Encrypt(ctx, data);

	/** Calculates CRC*/
	crc_result = myssn_CRC32(data_encrypt.padded_data, data_encrypt.pad_len);
	PRINTF("CRC: %u\r\n",crc_result);

	/**Converts int to string so it can be sent over TCP*/
	crc_str = (char *)&crc_result;
	/***Attach CRC to data to be sent*/
	for(int i = 0; i < CRC_LENGTH; i++)
	{
		data_encrypt.padded_data[(data_encrypt.pad_len + i)] = crc_str[i];
	}

	err = netconn_write(conn, data_encrypt.padded_data, (data_encrypt.pad_len + CRC_LENGTH), NETCONN_COPY);

	return err;
}
