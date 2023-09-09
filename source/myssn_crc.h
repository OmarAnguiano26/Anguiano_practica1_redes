/*
 * myssn_crc.h
 *
 *  Created on: Sep 9, 2023
 *      Author: Omar_PC
 */

#ifndef MYSSN_CRC_H_
#define MYSSN_CRC_H_
#include <stdint.h>

/**This function Init CRC32 before calling it
 * Used a default seed of 0xFFFFFFF*/
void myssn_InitCrc32();

/** This function performs checksum32 on data
 * params[]:
 * data: Array to perform checksum
 * len: length of the array
 *
 * return: Returns the value of checksum
 * */
uint32_t myssn_CRC32(uint8_t *data, uint8_t len);

#endif /* MYSSN_CRC_H_ */
