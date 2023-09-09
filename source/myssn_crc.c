/*
 * myssn_crc.c
 *
 *  Created on: Sep 9, 2023
 *      Author: Omar_PC
 */
#include "myssn_crc.h"
#include "fsl_crc.h"
#include <stdio.h>
#include "stdint.h"
/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
void myssn_InitCrc32()
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

uint32_t myssn_CRC32(uint8_t *data, uint8_t len)
{
	CRC_Type *base = CRC0;
	uint32_t checksum32;

    CRC_WriteData(base, (uint8_t *)&data[0], len);
    checksum32 = CRC_Get32bitResult(base);

    return checksum32;
}

