/*
 * EIL.h
 *Encryption and Integrity Layer
 *  Created on: Sep 2, 2023
 *      Author: Omar_PC
 */

#ifndef EIL_H_
#define EIL_H_
#include <myssn_aes.h>

void EIL_InitCRC32();

struct AES_ctx EIL_Init_AES();

err_t EIL_receive(struct netconn *conn, struct AES_ctx ctx, uint8_t *data_buff);

err_t EIL_send(struct netconn *conn, struct AES_ctx ctx, uint8_t *data);


#endif /* EIL_H_ */
