#ifndef _FWDEC_RULE_H_
#define _FWDEC_RULE_H_

#include "inc.h"

void get_ip_string(char *buf, uint32_t buf_len, uint32_t ip_addr);

void add_chain_rule(fw_chain *chain, fw_chain_rule *new_rule, int index);

void insert_chain_rule(fw_chain *chain, const int index, const uint32_t ip_start,
                       const uint32_t ip_end, const uint8_t type,
                       const uint16_t port, const uid_t uid,
                       const uint8_t action, const char *p_name,
                       const uint8_t direction);

void remove_chain_rule(fw_chain *chain, int index);

fw_chain_rule *find_matching_chain_rule(fw_chain *chain, const uint8_t type,
                                        const uint32_t ip_addr, const uint16_t port,
                                        const char *p_name, const uint8_t direction, const int uid);

void print_chain_rules(fw_chain *chain);

#endif