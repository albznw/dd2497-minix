#ifndef _FWTCP_FWTCP_H_
#define _FWTCP_FWTCP_H_

#include <sys/types.h>
#include <minix/config.h>
#include <minix/ds.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <regex.h>

//Used for keeping track of syn-scan and syn dos attacks
typedef struct tcpSynProt {
  struct tcpSynProt *next;
  uint32_t srcIp;
  uint32_t synCount; //The number of TCP syn packets recieved without subsequent ACK packets
  time_t timestamp;
} tcpSynProt;

#endif
