# Firewall Specification

This directory contains a firewall server for Minix. The firewall hooks into lwip, and filters packets based on a set of defined rules.

## Chain strucutre

The chains have the following structure

```c
typedef struct fw_chain {
  struct fw_chain_entry *head_entry;
  uid_t chain_id;
} fw_chain;
```
- The `head_entry` field refers to the first entry in every chain. If the chain is empty it's NULL.
- The `chain_id` field specifies what type of chain it is. Possible values are found in `proto.h`.

Every entry in a chain has this structure:

```c
typedef struct fw_chain_entry {
  struct fw_chain_rule *rule;
  struct fw_chain_entry *prev;
  struct fw_chain_entry *next;
} fw_chain_entry;
```

- The  `rule` field refers to a rule as defined below
- The `next` and`prev` fields are pointers to the next/previous entries in the chain.

```c
typedef struct fw_chain_rule {
  uint8_t type;
  uint8_t action;
  uint8_t direction;
  uid_t user;
  uint32_t ip_start;
  uint32_t ip_end;
  uint16_t port;
  char p_name[MAX_NAME_LEN];
} fw_chain_rule;

```

- The `type` field denotes the type of packet the rule matches (for instance TCP). The possible types are defined in `proto.h`. 
- The `action` field refers to the action to perform when a rule is matched; the possible values can be found in `fwdec.h`. 
- The `direction` field specifies if the rule matches incoming or outgoing packets; the possible values can be found in `fwrule.h`. 
- The `user` field specifies the user ID of the user which the rule applies to.
- The `ip_start` and `ip_end` fields refer to the start and end ranges for ip addresses.
- The `port` field specifies which port the rule applies to.
- The `p_name` field refers to the process name which is sending/receiving a packet.

If a field (except for `action`) is set to 0 or `NULL`, the field can be interpreted as matching any value.

## Matching rules
We have three different kind of rule lists (chains). The first chain contains rules that generally apply to individual users and can only be edited by privilged users. The second chain contains rules that apply to every user of the system, and the last chain contains rules for individual users that aren't necessarily privileged. When finding matching rules, the structure is as follows:

1. (If applicable) - Check for a matching rule in the privileged chain. If a matching rule is found, follow the action by the matching rule. If drop, drop the packet, and if allow continue to the non-privileged chain. If not match is found, continue to the global chain. 
2. Check for a matching rule in the global chain. If a matching rule is found, follow the action by the matching rule. If drop, drop the packet and if allow continue to user specific chain. If not matching rule is found, drop the packet.
3. Check for matching rules for specific users in the user chain. If no matching rule is found, allow the packet. Otherwise, follow action specified by matching rule. 
