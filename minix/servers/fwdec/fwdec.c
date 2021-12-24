/*
 * fwdec - Firewall decision server
 * Author: Thomas Peterson
 */

#include "inc.h"
#include "fwdec.h"

#include "fwrule.h"

#include <minix/com.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h> //File handling
#include <fcntl.h> //File handling flags
#include <sys/time.h> //System time

#include <minix/fwtcp.h>

/* Declare local functions. */
#ifdef FWDEC_DEBUG
static void debug_log_packet(const int type, const int result,
                             const uint32_t src_ip, const uint32_t dest_ip,
                             const uint16_t src_port, const uint16_t dest_port,
                             const char* p_name);
#endif

static void log(char* log_message);

static fw_rule* out_rules = NULL;
static fw_rule* in_rules = NULL;

static fw_chain* chain = NULL;

static inline uint32_t ip4_from_parts(uint8_t p1, uint8_t p2, uint8_t p3,
                                      uint8_t p4) {
  uint32_t result = p4 << 24 | p3 << 16 | p2 << 8 | p1;
  return result;
}

/* Global variables - Configurables */
const char* LOGFILE = "/var/log/fwdec";  // Where the log file should be placed

/*===========================================================================*
 *		            sef_cb_init_fresh *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t* info) {
  chain = (fw_chain*)malloc(sizeof(fw_chain));
  chain->head_entry = NULL;
  
  // Push default rules
  push_rule(&out_rules, IP_ANY, IP_ANY, FW_IP, 0, MIN_PRIORITY, FW_RULE_ACCEPT, NULL); 
  push_rule(&in_rules, IP_ANY, IP_ANY, FW_IP, 0, MIN_PRIORITY, FW_RULE_ACCEPT, NULL);

  // Push custom hard-coded rules
  uint32_t kth_ip = ip4_from_parts(130, 237, 28, 40);
  uint32_t google_dns = ip4_from_parts(8, 8, 8, 8);
  uint32_t youtube = ip4_from_parts(216, 58, 211, 14);
  // uint32_t local_host = ip4_from_parts(127, 0, 0, 1);
  // push_rule(&in_rules, google_dns, google_dns, FW_TCP, 0, MAX_PRIORITY,
  //           FW_RULE_REJECT, "dig");
  // push_rule(&in_rules, local_host, local_host, FW_TCP, 80, MAX_PRIORITY,
  //           FW_RULE_REJECT, "telnet");
  // push_rule(&out_rules, kth_ip, kth_ip, FW_IP, 0, MAX_PRIORITY, FW_RULE_REJECT,
  //           NULL);
  // push_rule(&out_rules, google_dns, google_dns, FW_UDP, 53, MAX_PRIORITY,
  //           FW_RULE_ACCEPT, "dig");
  // push_rule(&out_rules, IP_ANY, IP_ANY, FW_UDP, 0, MED_PRIORITY, FW_RULE_REJECT,
  //           "dig");
  uint32_t localhost = ip4_from_parts(127, 0, 0, 1);
  uint32_t internal_low = ip4_from_parts(10, 0, 2, 0);
  uint32_t internal_high = ip4_from_parts(10, 0, 2, 255);
  // Cannot fail
  print_chain_rules(chain);
  printf("Setting up rules\n\r");
  insert_chain_rule(chain, -1, kth_ip, kth_ip, 0, 0, 1000, FW_RULE_REJECT, NULL, OUT_RULE);
  insert_chain_rule(chain, -1, kth_ip, kth_ip, 0, 0, 0, FW_RULE_ACCEPT, NULL, OUT_RULE);
  insert_chain_rule(chain, -1, google_dns, google_dns, 0, 0, 0, FW_RULE_ACCEPT, NULL, OUT_RULE);
  insert_chain_rule(chain, -1, youtube, youtube, 0, 0, 0, FW_RULE_ACCEPT, NULL, OUT_RULE);
  insert_chain_rule(chain, -1, localhost, localhost, 0, 0, 0, FW_RULE_ACCEPT, NULL, OUT_RULE);
  insert_chain_rule(chain, -1, IP_ANY, IP_ANY, 0, 0, 0, FW_RULE_ACCEPT, NULL, IN_RULE);
  insert_chain_rule(chain, -1, internal_low, internal_high, 0, 0, 0, FW_RULE_ACCEPT, NULL, OUT_RULE);
  print_chain_rules(chain);
  printf("Weho2\n\r");
  

  printf("Firewall decision server started\n\r");
  return (OK);
}

/*===========================================================================*
 *				do_publish *
 *===========================================================================*/

int check_packet_match(const uint8_t type, const uint32_t src_ip, const uint16_t port, const char* p_name, uint8_t direction, uid_t uid){
  //printf("Checking packet - check_packet_match\n\r");
  fw_chain_rule* matched_rule = find_matching_chain_rule(chain, type, src_ip, port, p_name, direction, uid);
  // Whitelist firewall drops packets if no matching rule is found
  if (matched_rule == NULL) {
    printf("Packet dropped - no rule - check_packet_match\n\r");
    return LWIP_DROP_PACKET;
  }
  
  if (matched_rule->action == FW_RULE_REJECT) {
    printf("Packet dropped - by rule - check_packet_match\n\r");
    log("Packet dropped\n\r");
    return LWIP_DROP_PACKET;
  }
  char prettyip[64];
  get_ip_string(prettyip, 64, src_ip);
  printf("Packet kept - dir(%d) prettyip(%s) type(%d)\n\r", direction, prettyip, type);
  log("Packet accepted\n\r");
  return LWIP_KEEP_PACKET;
}

/*
int check_incoming(const uint8_t type, const uint32_t src_ip,
                   const uint16_t port, const char* p_name) {
  fw_rule* matched_rule =
      find_matching_rule(&in_rules, type, src_ip, port, p_name);

  if (matched_rule->action == FW_RULE_REJECT) {
    log("Packet dropped\n\r");
    return LWIP_DROP_PACKET;
  }

  log("Packet accepted\n\r");
  return LWIP_KEEP_PACKET;
}

int check_outgoing(const uint8_t type, const uint32_t dest_ip,
                   const uint16_t port, const char* p_name) {
  fw_rule* matched_rule =
      find_matching_rule(&out_rules, type, dest_ip, port, p_name);

  if (matched_rule->action == FW_RULE_REJECT) {
    log("Packet dropped\n\r");
    return LWIP_DROP_PACKET;
  }

  log("Packet accepted\n\r");
  return LWIP_KEEP_PACKET;
}
*/
int check_tcp_match(const uint32_t src_ip, const uint16_t port,
                       const char* p_name, uint64_t flags, uint8_t direction, uid_t uid) {
  // Let the TCP server do TCP related analysis such as SYN-FLOOD prevention
  if (fwtcp_check_packet(src_ip, flags) != LWIP_KEEP_PACKET) {
    log("Packet dropped\n\r");
    return LWIP_DROP_PACKET;
  }
  return check_packet_match(FW_TCP, src_ip, port, p_name, direction, uid);
}
/*
int check_incoming_tcp(const uint32_t src_ip, const uint16_t port,
                       const char* p_name, uint64_t flags) {
  // Let the TCP server do TCP related analysis such as SYN-FLOOD prevention
  if (fwtcp_check_packet(src_ip, flags) != LWIP_KEEP_PACKET) {
    log("Packet dropped\n\r");
    return LWIP_DROP_PACKET;
  }
  return check_incoming(FW_TCP, src_ip, port, p_name);
}
*/

int add_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
             uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name) {
  printf("fwdec: adding rule\n\r");
  switch (direction) {
    case 0:
      push_rule(&in_rules, ip_start, ip_end, type, port, priority, action,
                *p_name != '\0' ? p_name : NULL);
      break;
    default:
      push_rule(&out_rules, ip_start, ip_end, type, port, priority, action,
                *p_name != '\0' ? p_name : NULL);
      break;
  }
  return 0;
}

void list_rules(void) {
  print_chain_rules(chain);
  return;
}

int delete_rule(uint8_t direction, uint8_t type, uint8_t priority,
                uint8_t action, uint32_t ip_start, uint32_t ip_end,
                uint16_t port, char* p_name) {
  printf("fwdec: removing rule\n\r");
  switch (direction) {
    case 0:
      remove_rule(&in_rules, ip_start, ip_end, type, port, priority, action,
                  *p_name != '\0' ? p_name : NULL);
      break;
    default:
      remove_rule(&out_rules, ip_start, ip_end, type, port, priority, action,
                  *p_name != '\0' ? p_name : NULL);
      break;
  }
  return 0;
}

int check_packet(const int type, const uint32_t src_ip, const uint32_t dest_ip,
                 const uint16_t src_port, const uint16_t dest_port,
                 const char* p_name, const uint64_t flags, uid_t uid) {
  //printf("Checking packet - check_packet\n\r");
  int result;

  switch (type) {
    case FWDEC_QUERY_IP4_INC:
      result = check_packet_match(FW_IP, src_ip, 0, NULL, IN_RULE, uid);
      break;
    case FWDEC_QUERY_IP4_OUT:
      result = check_packet_match(FW_IP, dest_ip, 0, NULL, OUT_RULE, uid);
      break;
    case FWDEC_QUERY_TCP_INC:
      result = check_tcp_match(src_ip, src_port, p_name, flags, IN_RULE, uid);
      break;
    case FWDEC_QUERY_TCP_OUT:
      // TODO add TCP functions and logic
      result = check_packet_match(FW_TCP, dest_ip, dest_port, p_name, OUT_RULE, uid);
      break;
    case FWDEC_QUERY_UDP_INC:
      // TODO add UDP functions and logic
      result = check_packet_match(FW_UDP, src_ip, src_port, p_name, IN_RULE, uid);
      break;
    case FWDEC_QUERY_UDP_OUT:
      // TODO add UDP functions and logic
      result = check_packet_match(FW_UDP, dest_ip, dest_port, p_name, OUT_RULE, uid);
      break;
    case FWDEC_QUERY_RAW_INC:
      // TODO add RAW functions and logic
      result = check_packet_match(FW_RAW, src_ip, 0, p_name, IN_RULE, uid);
      break;
    case FWDEC_QUERY_RAW_OUT:
      // TODO add RAW functions and logic
      result = check_packet_match(FW_RAW, dest_ip, 0, p_name, OUT_RULE, uid);
      break;
    case FWDEC_QUERY_ICMP_INC:
      // TODO add ICMP functions and logic
      result = check_packet_match(FW_ICMP, src_ip, 0, NULL, IN_RULE, uid);
      break;
    case FWDEC_QUERY_ICMP_OUT:
      // TODO add ICMP functions and logic
      result = check_packet_match(FW_ICMP, dest_ip, 0, NULL, OUT_RULE, uid);
      break;
    default:
      printf("fwdec: warning, got illegal request %d\n\r", type);
      result = EINVAL;
  }

#ifdef FWDEC_DEBUG
  debug_log_packet(type, result, src_ip, dest_ip, src_port, dest_port, p_name);
#endif

  return result;
}

static void log(char* log_message) {
  // strncat(log_message, "\n\r", 1);
  int fd = open(LOGFILE, O_WRONLY | O_CREAT | O_APPEND);

  if (fd == -1) {
    printf("Warning: fwdec failed to open log file %s\n\r", LOGFILE);
    return;
  }

  int length = strlen(log_message);
  int written = write(fd, log_message, length);
  if (written != length) {
    printf("Warning: fwdec failed to write to log file");
  }
  close(fd);
}

#ifdef FWDEC_DEBUG
static void debug_log_packet(const int type, const int result,
                             const uint32_t src_ip, const uint32_t dest_ip,
                             const uint16_t src_port, const uint16_t dest_port,
                             const char* p_name) {
  unsigned char src_bytes[4] = {src_ip & 0xFF, (src_ip >> 8) & 0xFF,
                                (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF};
  unsigned char dest_bytes[4] = {dest_ip & 0xFF, (dest_ip >> 8) & 0xFF,
                                 (dest_ip >> 16) & 0xFF,
                                 (dest_ip >> 24) & 0xFF};
  char src_ip_str[64];
  char dest_ip_str[64];
  snprintf(src_ip_str, 64, "%d.%d.%d.%d", src_bytes[0], src_bytes[1],
           src_bytes[2], src_bytes[3]);
  snprintf(dest_ip_str, 64, "%d.%d.%d.%d", dest_bytes[0], dest_bytes[1],
           dest_bytes[2], dest_bytes[3]);

  char result_str[8];
  if (result == LWIP_DROP_PACKET) {
    strcpy(result_str, "BLOCKED");
  } else {
    strcpy(result_str, "ALLOWED");
  }

  switch (type) {
    case FWDEC_QUERY_TCP_INC:
      printf("TCP IN %s:%d <- %s:%d (%s) %s\n\r", dest_ip_str, dest_port,
             src_ip_str, src_port, p_name, result_str);
      break;
    case FWDEC_QUERY_TCP_OUT:
      printf("TCP OUT %s:%d -> %s:%d (%s) %s\n\r", src_ip_str, src_port,
             dest_ip_str, dest_port, p_name, result_str);
      break;
    case FWDEC_QUERY_UDP_INC:
      printf("UDP IN %s:%d <- %s:%d (%s) %s\n\r", dest_ip_str, dest_port,
             src_ip_str, src_port, p_name, result_str);
      break;
    case FWDEC_QUERY_UDP_OUT:
      printf("UDP OUT %s:%d -> %s:%d (%s) %s\n\r", src_ip_str, src_port,
             dest_ip_str, dest_port, p_name, result_str);
      break;
    case FWDEC_QUERY_RAW_INC:
      printf("RAW IN %s <- %s (%s) %s\n\r", dest_ip_str, src_ip_str, p_name,
             result_str);
      break;
    case FWDEC_QUERY_RAW_OUT:
      printf("RAW OUT %s -> %s (%s) %s\n\r", src_ip_str, dest_ip_str, p_name,
             result_str);
      break;
    case FWDEC_QUERY_ICMP_INC:
      printf("ICMP IN %s <- %s %s\n\r", dest_ip_str, src_ip_str, result_str);
      break;
    case FWDEC_QUERY_ICMP_OUT:
      printf("ICMP OUT %s -> %s %s\n\r", src_ip_str, dest_ip_str, result_str);
      break;
    default:
      break;
  }
}
#endif
