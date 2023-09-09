/*
 * EIL.h
 *Encryption and Integrity Layer
 *  Created on: Sep 2, 2023
 *      Author: Omar_PC
 */

#ifndef EIL_H_
#define EIL_H_
#include <myssn_aes.h>

/**Length of CRC, int*/
#define CRC_LENGTH 4u

/**Inits CRC32, needs to be called before calculating CRC
 * This function is to be called on tcpecho from the driver*/
void EIL_InitCRC32();

/**Links driver routine to tcpechoapp without using driver directly on app*/
struct AES_ctx EIL_Init_AES();

/**Receives data from client, decrypt it and calculates CRC to check integrity
 * params[]:
 * conn: pointer to the socket where the connection was done
 * ctx: Variable from AES init
 * data_buff: Direction of string where the data decrypted is placed
 *
 * return: Returns error status
 * */
err_t EIL_receive(struct netconn *conn, struct AES_ctx ctx, uint8_t *data_buff);

/**Sends the answer to client, data is encrypted and CRC is calculated and integrated into the frame so it can be sent
 * params[]:
 * conn: pointer to the socket where the connection was done
 * ctx: Variable from AES init
 * data: Data to be sent.
 *
 * return: Returns error status
 * */
err_t EIL_send(struct netconn *conn, struct AES_ctx ctx, uint8_t *data);


#endif /* EIL_H_ */
