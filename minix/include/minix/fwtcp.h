/* Prototypes and definitions for FWTCP interface. */

#ifndef _MINIX_FWTCP_H
#define _MINIX_FWTCP_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* fwtcp.c */

/* U32 */
int fwtcp_check_packet(uint32_t src_ip, uint64_t flags);

#endif /* _MINIX_FWTCP_H */
