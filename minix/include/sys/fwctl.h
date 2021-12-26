#ifndef _SYS__FWCTL_H
#define _SYS__FWCTL_H

#include <sys/types.h>

#define INC_CHAIN 0
#define OUT_CHAIN 1

#define DROP_PACKET 1
#define ACCEPT_PACKET 2

int fwdec_add_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name);

int fwdec_delete_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name);

int fwdec_list_rules(int chain_id);

#endif /* _SYS__SVRCTL_H */
