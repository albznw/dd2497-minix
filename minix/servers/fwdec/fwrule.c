#include "fwrule.h"
#include "inc.h"
#include <sys/fwctl.h>

/**
 * Get a string representation of an uint32_t IP address.
 * 
 * @param buf Buffer to place the IP string in
 */
void get_ip_string(char *buf, uint32_t buf_len, uint32_t ip_addr) {
  unsigned char bytes[4] = {ip_addr & 0xFF, (ip_addr >> 8) & 0xFF,
                            (ip_addr >> 16) & 0xFF, (ip_addr >> 24) & 0xFF};
  snprintf(buf, buf_len, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
 * Adds a new rule in the chain by creating a new entry in the chain containing the specified rule. 
 * If the wanted index is not found the rule will be placed in the end of the chain. 
 * A fast way to add rules to the end of the list is to add them at index -1.
 *
 * @param new_rule pointer to the new rule on the heap
 * @param index wanted index
 */
void add_chain_rule(fw_chain *chain, fw_chain_rule *new_rule, int index, const uid_t effuid) {
  printf("Adding new rule %d %d %s\n\r", new_rule->type, new_rule->action,
         new_rule->direction == OUT_RULE ? "OUT" : "IN");

  fw_chain_entry *c_entry = chain->head_entry;
  fw_chain_entry *new_entry = (fw_chain_entry *)malloc(sizeof(fw_chain_entry));

  // Create a new entry from the rule to add
  new_entry->rule = new_rule;
  new_entry->prev = NULL;
  new_entry->next = NULL;

  // If we have no rules in the chain yet the new rule will be the head.
  if (chain->head_entry == NULL) {
    new_entry->prev = NULL;
    new_entry->next = NULL;
    chain->head_entry = new_entry;
    return;
  }

  int c_index = 0;
  fw_chain_entry *last_entry = NULL;

  // Iterate over entries until index is found or we run out of entries
  while (c_entry) {

    // Skip rule if it does not belong to user
    if (c_entry->rule->user != effuid && chain->chain_id == USER_CHAIN_ID) {
      last_entry = c_entry;
      c_entry = c_entry->next;
      continue;
    }

    // Add new entry before c_entry with desired index
    if (index == c_index) {
      // The entry that will be before the new entry;
      fw_chain_entry *tmp_prev = c_entry->prev;
      // Update entry at index (that will be after new entry) to point back to new entry
      c_entry->prev = new_entry;
      // Update entry pointers of new entry
      new_entry->next = c_entry;
      new_entry->prev = tmp_prev;
      // Update entry that will be before the new entry (if new entry isn't first) to point forward to new entry
      if (tmp_prev != NULL) {
        tmp_prev->next = new_entry;
      } else {
        // The new entry will be the first entry of the chain
        chain->head_entry = new_entry;
      }
      return;
    }
    
    c_index++;
    last_entry = c_entry;
    c_entry = c_entry->next;
  }

  // Index not found, placing the new rule at the end
  last_entry->next = new_entry;
  new_entry->prev = last_entry;
}

/**
 * Inserts a new rule in the chain at the specified index.
 * If the wanted index is not found the rule will be placed in the end of the chain. 
 * A fast way to add rules to the end of the list is to add them at index -1.
 * 
 * @param index wanted index
 */
void insert_chain_rule(fw_chain *chain, const int index,
                       const uint32_t ip_start,
                       const uint32_t ip_end, const uint8_t type,
                       const uint16_t port, const uid_t uid,
                       const uint8_t action, const char *p_name,
                       const uint8_t direction, const uid_t effuid) {

  // Check permissions
  if (effuid != 0 && chain->chain_id != USER_CHAIN_ID) {
    printf("Error: You need permissions to add new rules to the privileged- and global chains\n\r");
    return;
  }

  // New rule and params
  fw_chain_rule *new_rule =
      (struct fw_chain_rule *)malloc(sizeof(fw_chain_rule));
  new_rule->type = type;
  new_rule->port = port;
  new_rule->user = uid;
  new_rule->ip_start = ip_start;
  new_rule->ip_end = ip_end;
  new_rule->action = action;
  new_rule->direction = direction;  // Package in or out

  if (p_name != NULL) {
    strncpy(new_rule->p_name, p_name, MAX_NAME_LEN);
  } else {
    new_rule->p_name[0] = '\0';  // Empty string
  }

  // Find entries to modify. Add to chain entry linked list
  add_chain_rule(chain, new_rule, index, effuid);
}

/**
 * Remove the rule at the given index of the specified chain.
 */
void remove_chain_rule(fw_chain *chain, int index, const uid_t effuid) {

  if (effuid != 0 && chain->chain_id != USER_CHAIN_ID ) {
    printf("Error: You need root permissions to remove rules from the"
    "privileged- and global chains\n\r");
    return;
  }

  fw_chain_entry *curr_entry = chain->head_entry;
  int curr_ind = 0;
  // Iterate over entries until index is found or we run out of entries
  while (curr_entry != NULL) {
    fw_chain_rule *curr_rule = curr_entry->rule;
    if (curr_rule == NULL) {
      printf("Error: When trying to remove a rule a chain-entry without an associated rule was found!\n\r");
      return;
    }

    if (curr_rule->user != effuid && chain->chain_id == USER_CHAIN_ID) {
      // Jump over this rule if it does not belong to the effective user
      curr_entry = curr_entry->next;
      continue;
    }
    
    if (curr_ind == index) {
      break;
    }
    curr_entry = curr_entry->next;
    curr_ind++;
  }

  if (curr_entry != NULL) {
    // Update the entry coming before the one we delete
    if (curr_entry->prev != NULL) {
      curr_entry->prev->next = curr_entry->next;
    } else {
      // Rule was the first of the list. Need to update head.
      chain->head_entry = curr_entry->next;
    }
    // Update the entry coming after the one we delete
    if (curr_entry->next != NULL) {
      curr_entry->next->prev = curr_entry->prev;
    }
    free(curr_entry->rule);
    free(curr_entry);
  } else {
    printf("Did not find a rule to delete at index %d\n\r", index);
  }
}

/**
 * Minix saves the ipaddresses flipped, meaning that the last octet is saved 
 * as the most significant bits. This function flips it back so that we can
 * compare ip ranges with an ip address.
 */
uint32_t flip_ip(const uint32_t ip_addr){
  return ( ( ip_addr >> 24 ) & 0x000000FF ) | ( ( ip_addr >>  8 ) & 0x0000FF00 )
    | ( ( ip_addr <<  8 ) & 0x00FF0000 ) | ( ( ip_addr << 24 ) & 0xFF000000 );
}

/**
 * Checks whether or not a specified IP address is within an IP address range.
 */
int is_ip_in_range(const uint32_t ip_addr, const uint32_t ip_addr_start, const uint32_t ip_addr_end){
  return flip_ip(ip_addr_start) <= flip_ip(ip_addr) && flip_ip(ip_addr) <= flip_ip(ip_addr_end);
}

/**  
  TODO5: Document what this function does, and how it works once it has been fixed to work 
  for multiple chains.
*/
fw_chain_rule *find_matching_chain_rule(fw_chain *chain, const uint8_t type,
                                        const uint32_t ip_addr, const uint16_t port,
                                        const char *p_name, const uint8_t direction, const int uid) {
  if (chain == NULL) {
    printf("WARN: Chain null - find_matching_chain_rule\n\r");
    return NULL;
  }
  fw_chain_entry *c_entry = chain->head_entry;
  char prettyip[64];
  get_ip_string(prettyip, 64, ip_addr);

  while (c_entry != NULL) {

    //  Check for every rule that the arguments match, if a match is found return rule
    //  otherwise return null ( = no rule matching)
    if (
        (c_entry->rule->type == TYPE_ANY || c_entry->rule->type == type) &&
        ((c_entry->rule->ip_start == IP_ANY && c_entry->rule->ip_end == IP_ANY) || is_ip_in_range(ip_addr, c_entry->rule->ip_start, c_entry->rule->ip_end)) &&
        (c_entry->rule->port == PORT_ANY || c_entry->rule->port == port) &&
        (strcmp(c_entry->rule->p_name, PNAME_ANY) == 0 || (p_name != NULL && strcmp(c_entry->rule->p_name, p_name) == 0)) &&
        (c_entry->rule->user == NO_USER_ID || c_entry->rule->user == uid) &&
        (c_entry->rule->direction == DIR_ANY || c_entry->rule->direction == direction)) {
      char prettyip_start_rule[64], prettyip_end_rule[64];
      get_ip_string(prettyip_start_rule, 64, c_entry->rule->ip_start);
      get_ip_string(prettyip_end_rule, 64, c_entry->rule->ip_end);

      printf("Found matching rule: user(%d) check_ip(%s) ip(%s-%s) type(%d) name(%s) dir(%s) action(%d)\r\n", c_entry->rule->user, prettyip, prettyip_start_rule, prettyip_end_rule, c_entry->rule->type, c_entry->rule->p_name, c_entry->rule->direction == DIR_ANY ? "ANY" : c_entry->rule->direction == IN_RULE ? "IN" : "OUT", c_entry->rule->action);
      return c_entry->rule;
    }
    c_entry = c_entry->next;
  }

  printf("Could not find matching rule: type(%d) ip(%d) prettyip(%s) port(%d) name(%s), dir(%d), uid(%d)\r\n", type, ip_addr, prettyip, port, (p_name == NULL ? "" : p_name), direction, uid);
  return NULL;
}

/**
 * Print the specified chain of rules.
 */
void print_chain_rules(fw_chain *chain, const uid_t effuid) {
  printf("Printing rules for chain %d\n\r", chain->chain_id);
  printf("%-5s%-8s%-10s%-8s%-16s%-16s%-6s%-16s\n\r", "type", "action", "direction", "user ID",
         "start", "end", "port", "name");
  fw_chain_entry *curr_entry = chain->head_entry;
  while (curr_entry != NULL) {
    
    
    fw_chain_rule *curr_rule = curr_entry->rule;
    if (curr_rule == NULL) {
      printf("Error: When trying to list rules a chain-entry without an associated rule was found!\n\r");
      return;
    }

    if(chain->chain_id == USER_CHAIN_ID){
      if(effuid != 0 && curr_rule->user != effuid) {
        curr_entry = curr_entry->next;
        continue;
      }
    }

    char action[7];
    char type_str[5];
    char start_ip_str[64];
    char end_ip_str[64];
    char direction_str[10];
    get_ip_string(start_ip_str, 64, curr_rule->ip_start);
    get_ip_string(end_ip_str, 64, curr_rule->ip_end);
    if (curr_rule->action == DROP_PACKET) {
      strncpy(action, "REJECT", 7);
    } else {
      strncpy(action, "ACCEPT", 7);
    }
    if (curr_rule->type == FW_TCP) {
      strncpy(type_str, "TCP", 5);
    } else if (curr_rule->type == FW_UDP) {
      strncpy(type_str, "UDP", 5);
    } else if (curr_rule->type == FW_ICMP) {
      strncpy(type_str, "ICMP", 5);
    } else if (curr_rule->type == FW_RAW) {
      strncpy(type_str, "RAW", 5);
    } else {
      strncpy(type_str, "IP", 5);
    }

    if (curr_rule->direction == IN_RULE) {
      strncpy(direction_str, "INGRESS", 10);
    } else {
      strncpy(direction_str, "EGRESS", 10);
    }
    printf("%-5s%-8s%-10s%-8d%-16s%-16s%-6d%-16s\n\r", type_str, action,
           direction_str, curr_rule->user, start_ip_str, end_ip_str, curr_rule->port,
           curr_rule->p_name);

    curr_entry = curr_entry->next;
  }
  printf("\n\r");
  return;
}
