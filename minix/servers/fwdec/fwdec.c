/*
 * fwdec - Firewall decision server
 * Author: Thomas Peterson
 */

#include "inc.h"
#include "fwdec.h"
#include <minix/com.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h> //File handling
#include <fcntl.h> //File handling flags
#include <sys/time.h> //System time


/* Declare local functions. */
int check_ip4_headers(uint32_t src_ip, uint32_t dst_ip);
void logToLogfile(char* logfile,char* logEntry, int length);

/* Global variables */
static int mode = MODE_NOTSET;

/* Global variables - Configurables */
const char *LOGFILE = "/var/log/fwdec"; //Where the log file should be placed
const int defaultMode = MODE_WHITELIST; //Might be exported to config file in the future
int TCP_PROTECTION_TIMEOUT = 30; //The amount of seconds before a tcp protection entry is reset
int TCP_MAX_SYNCOUNT = 5; //The maximum amount of suspicious SYN packets allowed from a host

static inline uint32_t ip4_from_parts(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4)
{
  uint32_t result = p4 << 24 | p3 << 16 | p2 << 8 | p1;
  return result;
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                        *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  printf("Firewall decision server started\n");
  return(OK);
}

/*===========================================================================*
 *				do_publish				                                     *
 *===========================================================================*/

int check_ip4_headers(uint32_t src_ip, uint32_t dst_ip)
{
  uint32_t kth_ip = ip4_from_parts(130, 237, 28, 40);

  if (dst_ip == kth_ip) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

void logToLogfile(char* logFile,char* logEntry, int length){
  //Writes logentry to logfile using vfs syscall wrappers
  int fd = open(logFile, O_WRONLY|O_CREAT|O_APPEND);
  if (fd == -1){
    printf("Warning: fwdec failed to open log file %s\n",logFile);
  }

  int bytesWritten = write(fd, logEntry, length);
  if (bytesWritten != length){
    printf("Warning: fwdec failed to write to log file");
  }
  close(fd);
}
