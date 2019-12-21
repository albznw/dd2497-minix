# Firewall Specification

This directory contains a firewall server for Minix. The firewall hooks into lwip, and filters packets based on a set of defined rules.

## Rule strucutre

Rules in fwdec have the structure:

```c
struct fw_rule {
  uint32_t ip_start;
  uint32_t ip_end;
  char *p_name;
  uint8_t action;
  struct fw_rule *next;
};
```

The two first fields refer to the start and end ranges for ip addresses. The `p_name` field refers to the process name which is sending/receiving a packet. The `action` field refers to the action to perform when a rule is matched; the possible values can be found in `fwdec.h`. The `next` field refers to the next rule in the list of rules.

If a field (except for `action` and `next`) is set to 0 or `NULL`, the field can be interpreted as matching any value.

## Matching rules

We have separate rule lists for incoming and outgoing packets. Rules are matched using an importance metric based on fields that have been set. The importance is defined as follows (in order of decreasing importance):

1. Exact IP
2. IP within bounds
3. Any IP

If the process name is set for a rule, then the rule takes precendece over rules that do not have the process name set.

Example: Rule A blocks outgoing packets to kth.se for all processes. Rule B allows outgoing packets to [kth.se-10 .. kth.se+10], and it has `p_name` set to telnet. Even though rule A has a higher importance level, packets to kth.se will be allowed from telnet.