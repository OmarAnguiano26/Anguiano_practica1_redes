/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "tcpecho.h"

#include "lwip/opt.h"

#if LWIP_NETCONN

#include "lwip/sys.h"
#include "lwip/api.h"
#include "EIL.h"
#include "aes.h"
#include <stdio.h>

/* Server IP address*/
#define configSERVER_ADDR0 192
#define configSERVER_ADDR1 168
#define configSERVER_ADDR2 0
#define configSERVER_ADDR3 100
/*-----------------------------------------------------------------------------------*/

/**Buffer to convert received data to char*/
static char tcpecho_app_data_print[256] = {0};
static ip4_addr_t server_ip_address;
/*-----------------------------------------------------------------------------------*/
static void
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);
  struct AES_ctx ctx;
  AES_struct_data data_encrypt;
  uint32_t crc_result;
  AES_struct_data decrypt_data;
  uint8_t crc_str[] = {};
  void * data_send;

  /**Inits CRC and AES*/
  EIL_InitCrc32();
  ctx = EIL_AES_Init();


  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 7);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 7);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */
  netconn_listen(conn);

  while (1) {

    /* Grab new connection. */
    err = netconn_accept(conn, &newconn);
    /*printf("accepted new connection %p\n", newconn);*/
    /* Process the new connection. */
    if (err == ERR_OK) {
      struct netbuf *buf;
      void *data;
      u16_t len;
      uint8_t i = 0;

      while ((err = netconn_recv(newconn, &buf)) == ERR_OK) {
        /*printf("Recved\n");*/
        do {
             netbuf_data(buf, &data, &len);
             /**Encrypts data*/
             data_encrypt = EIL_Encrypt(ctx, data);
             /**CRC*/
             crc_result = EIL_CRC32(data_encrypt.padded_data, data_encrypt.pad_len);
             /**Conver crc to str*/
             sprintf(crc_str, "%d", crc_result);
             strcat(data_encrypt.padded_data, crc_str);
             err = netconn_write(newconn, data_encrypt.padded_data, data_encrypt.pad_len, NETCONN_COPY);
#if 0
            if (err != ERR_OK) {
              printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
            }
#endif
            i++;
        } while (netbuf_next(buf) >= 0);
        netbuf_delete(buf);
      }
      /*printf("Got EOF, looping\n");*/
      /* Close connection and discard connection identifier. */
      netconn_close(newconn);
      netconn_delete(newconn);
    }
  }
}

static void
tcpecho_thread_client(void *arg)
{

	  struct netconn *conn, *newconn;
	  err_t err,com_err;
	  LWIP_UNUSED_ARG(arg);

	  while(1)
	  {
		  conn = netconn_new(NETCONN_TCP);
		  /**Connect to server*/
		  IP4_ADDR(&server_ip_address, configSERVER_ADDR0, configSERVER_ADDR1, configSERVER_ADDR2, configSERVER_ADDR3);
		  /**Delay to connect the server*/
		  PRINTF("Start Server\n");
		  vTaskDelay(5000);
		  err = netconn_connect(conn, &server_ip_address,7);
		  /**Successfully connected to server*/
		  if(err == ERR_OK)
		  {
			  /**Start writing*/
			  struct netbuf *buf;
			  void *data;
			  u16_t len;

			  data = (void*)"Hello Server";
			  len = strlen((const char*)data);
			  com_err = netconn_write(conn, data, len, NETCONN_COPY);
			  if (com_err != ERR_OK)
			  {
				  PRINTF("tcp_app: Error in write \n");
			  }
			  /**Start receiving from server*/
			  com_err = netconn_recv(conn, &buf);
			  if(com_err == ERR_OK)
			  {
				  PRINTF("Received from Server:");
				  do
				  {
					  netbuf_data(buf, &data, &len);
					  /**Copy received data to a string so it can be printed on console*/
					  memcpy(tcpecho_app_data_print, data, len);
					  PRINTF("%s\r\n", tcpecho_app_data_print);
				  }
				  while(netbuf_next(buf) >= 0);
				  netbuf_delete(buf);
			  }
			  else
			  {
				  PRINTF("Error in receivig\n");
			  }
			  netconn_delete(conn);
			  PRINTF("Connection closed\n");

		  }
	}
}

/*-----------------------------------------------------------------------------------*/
void
tcpecho_init(void)
{
  sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
/*-----------------------------------------------------------------------------------*/

#endif /* LWIP_NETCONN */
