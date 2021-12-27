#ifndef _SYS__FWCTL_H
#define _SYS__FWCTL_H

#include <sys/types.h>

#define IN_RULE 1
#define OUT_RULE 2

#define DROP_PACKET 1
#define ACCEPT_PACKET 2

int fwdec_add_rule(uint8_t direction, uint8_t type, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name,
						uint32_t chain_id, uint32_t index);

int fwdec_delete_rule(uint8_t direction, uint8_t type, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name,
						uint32_t chain_id, uint32_t index);

int fwdec_list_rules(int chain_id);

#endif /* _SYS__SVRCTL_H */
