#include "inc.h"
#include "fwtcp.h"

#include <sys/time.h>

#define TCP_PROTECTION_TIMEOUT 30 //The amount of seconds before a tcp protection entry is reset
#define TCP_MAX_SYNCOUNT 5 //The maximum amount of suspicious SYN packets allowed from a host

static tcpSynProt* tcpSynConnections = 0;



/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  return(OK);
}

/*===========================================================================*
 *				do_check_packet				     *
 *===========================================================================*/
int do_check_packet(message *m_ptr)
{
  uint8_t syn = 0, ack = 0;

  if(FWDEC_GET_TCP_SYN(m_ptr->m_fwdec_ip4.flags)){
    syn = 1;
  }
  if(FWDEC_GET_TCP_ACK(m_ptr->m_fwdec_ip4.flags)){
    ack = 1;
  }
  if(FWDEC_GET_TCP_FIN(m_ptr->m_fwdec_ip4.flags)){
  }
  printf("\n");

  return tcpSynProtection(m_ptr->m_fwdec_ip4.src_ip, syn, ack);
}

int tcpSynProtection(uint32_t srcIp, uint8_t syn, uint8_t ack){
  //Keeps track of which ips have sent syn packets and if they have sent acks for these
  //Blacklists misbehaving clients

  time_t timestamp = time(NULL);

  //find the matching entry
  tcpSynProt* previous = 0;
  tcpSynProt* current = tcpSynConnections;
  while(current != 0){
    if (current->srcIp == srcIp){//Can easily be compared since both are stored as ints! :)
      break;
    }
    previous = current;
    current = current->next;
  }

  if (current == 0){//Source Ip was not found in list
    tcpSynProt* newEntry = malloc(sizeof(tcpSynProt));
    newEntry->srcIp = srcIp;
    newEntry->synCount = 0;
    newEntry->timestamp = timestamp;

    //Add to list
    if (tcpSynConnections == 0){//list is empty
      tcpSynConnections = newEntry;
    }
    else if (previous == 0){//list has one element
      tcpSynConnections->next = newEntry;
    }
    else{
      previous->next = newEntry;
    }

    current = newEntry;
  }

  //Check for too many unjustified syns
  if (current->synCount >= TCP_MAX_SYNCOUNT){
    return LWIP_DROP_PACKET;
  }

  //Reset count if too much time has passed
  if((timestamp - current->timestamp) > TCP_PROTECTION_TIMEOUT){
    current->timestamp = timestamp;
    current->synCount = 0;
  }

  //Update synCount
  current->synCount = ((syn == 0 && ack == 1 && current->synCount == 0)?0:current->synCount+syn-ack);

  return LWIP_KEEP_PACKET;
}
