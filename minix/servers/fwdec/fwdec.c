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
  // push_rule(&out_rules, IP_ANY, IP_ANY, FW_IP, 0, MIN_PRIORITY,
  // FW_RULE_ACCEPT, NULL); push_rule(&in_rules, IP_ANY, IP_ANY, FW_IP, 0,
  // MIN_PRIORITY, FW_RULE_ACCEPT, NULL);

  // Push custom hard-coded rules
  uint32_t kth_ip = ip4_from_parts(130, 237, 28, 40);
  uint32_t google_dns = ip4_from_parts(8, 8, 8, 8);
  uint32_t local_host = ip4_from_parts(127, 0, 0, 1);
  push_rule(&in_rules, google_dns, google_dns, FW_TCP, 0, MAX_PRIORITY,
            FW_RULE_REJECT, "dig");
  push_rule(&in_rules, local_host, local_host, FW_TCP, 80, MAX_PRIORITY,
            FW_RULE_REJECT, "telnet");

  push_rule(&out_rules, kth_ip, kth_ip, FW_IP, 0, MAX_PRIORITY, FW_RULE_REJECT,
            NULL);
  push_rule(&out_rules, google_dns, google_dns, FW_UDP, 53, MAX_PRIORITY,
            FW_RULE_ACCEPT, "dig");
  push_rule(&out_rules, IP_ANY, IP_ANY, FW_UDP, 0, MED_PRIORITY, FW_RULE_REJECT,
            "dig");

  printf("Firewall decision server started\n");
  return (OK);
}

/*===========================================================================*
 *				do_publish *
 *===========================================================================*/

int check_incoming(const uint8_t type, const uint32_t src_ip,
                   const uint16_t port, const char* p_name) {
  fw_rule* matched_rule =
      find_matching_rule(&in_rules, type, src_ip, port, p_name);

  if (matched_rule->action == FW_RULE_REJECT) {
    log("Packet dropped\n");
    return LWIP_DROP_PACKET;
  }

  log("Packet accepted\n");
  return LWIP_KEEP_PACKET;
}

int check_outgoing(const uint8_t type, const uint32_t dest_ip,
                   const uint16_t port, const char* p_name) {
  fw_rule* matched_rule =
      find_matching_rule(&out_rules, type, dest_ip, port, p_name);

  if (matched_rule->action == FW_RULE_REJECT) {
    log("Packet dropped\n");
    return LWIP_DROP_PACKET;
  }

  log("Packet accepted\n");
  return LWIP_KEEP_PACKET;
}

int check_incoming_tcp(const uint32_t src_ip, const uint16_t port,
                       const char* p_name, uint64_t flags) {
  // Let the TCP server do TCP related analysis such as SYN-FLOOD prevention
  if (fwtcp_check_packet(src_ip, flags) != LWIP_KEEP_PACKET) {
    log("Packet dropped\n");
    return LWIP_DROP_PACKET;
  }
  return check_incoming(FW_TCP, src_ip, port, p_name);
}

int add_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
             uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name) {
  printf("fwdec: adding rule\n");
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
  print_rules(&in_rules, "INC");
  print_rules(&out_rules, "OUT");
  return;
}

int delete_rule(uint8_t direction, uint8_t type, uint8_t priority,
                uint8_t action, uint32_t ip_start, uint32_t ip_end,
                uint16_t port, char* p_name) {
  printf("fwdec: removing rule\n");
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
                 const char* p_name, const uint64_t flags) {
  int result;

  switch (type) {
    case FWDEC_QUERY_IP4_INC:
      result = check_incoming(FW_IP, src_ip, 0, NULL);
      break;
    case FWDEC_QUERY_IP4_OUT:
      result = check_outgoing(FW_IP, dest_ip, 0, NULL);
      break;
    case FWDEC_QUERY_TCP_INC:
      result = check_incoming_tcp(src_ip, src_port, p_name, flags);
      break;
    case FWDEC_QUERY_TCP_OUT:
      // TODO add TCP functions and logic
      result = check_outgoing(FW_TCP, dest_ip, dest_port, p_name);
      break;
    case FWDEC_QUERY_UDP_INC:
      // TODO add UDP functions and logic
      result = check_incoming(FW_UDP, src_ip, src_port, p_name);
      break;
    case FWDEC_QUERY_UDP_OUT:
      // TODO add UDP functions and logic
      result = check_outgoing(FW_UDP, dest_ip, dest_port, p_name);
      break;
    case FWDEC_QUERY_RAW_INC:
      // TODO add RAW functions and logic
      result = check_incoming(FW_RAW, src_ip, 0, p_name);
      break;
    case FWDEC_QUERY_RAW_OUT:
      // TODO add RAW functions and logic
      result = check_outgoing(FW_RAW, dest_ip, 0, p_name);
      break;
    case FWDEC_QUERY_ICMP_INC:
      // TODO add ICMP functions and logic
      result = check_incoming(FW_ICMP, src_ip, 0, NULL);
      break;
    case FWDEC_QUERY_ICMP_OUT:
      // TODO add ICMP functions and logic
      result = check_outgoing(FW_ICMP, dest_ip, 0, NULL);
      break;
    default:
      printf("fwdec: warning, got illegal request %d\n", type);
      result = EINVAL;
  }

#ifdef FWDEC_DEBUG
  debug_log_packet(type, result, src_ip, dest_ip, src_port, dest_port, p_name);
#endif

  return result;
}

static void log(char* log_message) {
  // strncat(log_message, "\n", 1);
  int fd = open(LOGFILE, O_WRONLY | O_CREAT | O_APPEND);

  if (fd == -1) {
    printf("Warning: fwdec failed to open log file %s\n", LOGFILE);
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
      printf("TCP IN %s:%d <- %s:%d (%s) %s\n", dest_ip_str, dest_port,
             src_ip_str, src_port, p_name, result_str);
      break;
    case FWDEC_QUERY_TCP_OUT:
      printf("TCP OUT %s:%d -> %s:%d (%s) %s\n", src_ip_str, src_port,
             dest_ip_str, dest_port, p_name, result_str);
      break;
    case FWDEC_QUERY_UDP_INC:
      printf("UDP IN %s:%d <- %s:%d (%s) %s\n", dest_ip_str, dest_port,
             src_ip_str, src_port, p_name, result_str);
      break;
    case FWDEC_QUERY_UDP_OUT:
      printf("UDP OUT %s:%d -> %s:%d (%s) %s\n", src_ip_str, src_port,
             dest_ip_str, dest_port, p_name, result_str);
      break;
    case FWDEC_QUERY_RAW_INC:
      printf("RAW IN %s <- %s (%s) %s\n", dest_ip_str, src_ip_str, p_name,
             result_str);
      break;
    case FWDEC_QUERY_RAW_OUT:
      printf("RAW OUT %s -> %s (%s) %s\n", src_ip_str, dest_ip_str, p_name,
             result_str);
      break;
    case FWDEC_QUERY_ICMP_INC:
      printf("ICMP IN %s <- %s %s\n", dest_ip_str, src_ip_str, result_str);
      break;
    case FWDEC_QUERY_ICMP_OUT:
      printf("ICMP OUT %s -> %s %s\n", src_ip_str, dest_ip_str, result_str);
      break;
    default:
      break;
  }
}
#endif
