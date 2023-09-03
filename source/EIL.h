/*
 * EIL.h
 *Encryption and Integrity Layer
 *  Created on: Sep 2, 2023
 *      Author: Omar_PC
 */

#ifndef EIL_H_
#define EIL_H_

static void EIL_InitCrc32();
uint32_t EIL_CRC32(uint8_t *data, uint8_t len);
AES_ctx EIL_AES_Init();
uint8_t * EIL_Encrypt(AES_ctx ctx, uint8_t *data);

#endif /* EIL_H_ */
