
#include <sys/fwctl.h>
#include <sys/types.h>
#include <ctype.h>
#include <lib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define	GETOPTSTR	"ADi:Ln:p:t:"

static void __dead
usage(void) {
	fprintf(stderr,
	    "usage:\t%s\n\t   %s\n\n%s\n",
	    "firewall -ADL [-i 0-255] [-p port] [-n pname] [-t IP|TCP|UDP|ICMP|RAW]",
	    "chain_id index INC|OUT REJECT|ACCEPT start_ip [end_ip]",
        "For more information consult the manual using \"man firewall\"");
	exit(1);
}

int main(int argc, char **argv) {
	extern char *optarg;
	extern int optind;

    uint32_t start_addr = 0, end_addr = 0;
    uint8_t method = 0, direction = 0, action = 0, importance = 255, type = 0;
    uint16_t port = 0;
    int index = 0;
    int chain_id = 0;
    uid_t uid = 0; // TODO5: Is this the correct default value?
    char name[16]; name[0] = '\0';
    char type_str[5];
    char direction_str[4];
    char action_str[7];

    /* This is not for security since the SYSCALL will fail anyway. This just saves us from making a useless SYSCALL*/
	if (geteuid() != 0) {
		fprintf(stderr, "Need root permissions to view or edit firewall rules.\n");
        exit(1);
	}

    int ch;
    while ((ch = getopt(argc, argv, GETOPTSTR)) != -1) {
        switch ((char) ch) {
        case 'A':
            if(!method){
                method = 1;
            } else {
                fprintf(stderr, "Error: must choose only one of -A, -D, -L.\n\n");
                usage();
            }
            break;
        case 'D':
            if(!method){
                method = 2;
            } else {
                fprintf(stderr, "Error: must choose only one of -A, -D, -L.\n\n");
                usage();
            }
            break;
        case 'L':
            if(!method){
                method = 3;
            } else {
                fprintf(stderr, "Error: must choose only one of -A, -D, -L.\n\n");
                usage();
            }
            break;
        // TODO5: remove priority
        case 'i':
            {
                char* end;
                long number = strtoul(optarg, &end, 10);
                if (*end == '\0' && number < 256){
                    importance = number;
                } else {
                    fprintf(stderr, "Error: invalid importance \"%s\", must be 0-255.\n\n", optarg);
                    usage();        
                }
            }
            break;
        case 'n':
            strncpy(name, optarg, 16);  // TODO Maybe check name for invalid characters
            break;
        case 'p':
            {
                char* end;
                long number = strtoul(optarg, &end, 10);
                if (*end == '\0' && number < 65536){
                    port = number;
                } else {
                    fprintf(stderr, "Error: invalid port \"%s\", must be 0-65535.\n\n", optarg);
                    usage();        
                }
            }
            break;
        case 't':
            {
                strncpy(type_str, optarg, 5);
                if(strncmp(type_str, "IP", 5) == 0) {
                    type = 0;
                } else if (strncmp(type_str, "TCP", 5) == 0){
                    type = 1;
                } else if (strncmp(type_str, "UDP", 5) == 0){
                    type = 2;
                } else if (strncmp(type_str, "ICMP", 5) == 0){
                    type = 3;
                } else if (strncmp(type_str, "RAW", 5) == 0){
                    type = 4;
                } else {
                    fprintf(stderr, "Error: did not recognize protocol type \"%s\". %s\n\n",
                                    argv[0], "Should be either IP, TCP, UDP, ICMP or RAW.");
                    usage();
                }                
            }
            break;
        default:
            fprintf(stderr, "Error: unrecognized argument \"-%c\", must be 0-255.\n\n", (char) ch);
            usage();
            break;
        }
    }

	argc -= optind;
	argv += optind;

    if(argc == 0) {
        fprintf(stderr, "Error: No arguments given.\n\n");
        usage();
    }
    // Parse chain id
    // TODO5 Sanitize?
    chain_id = atoi(argv[0]);
    
    if(method == 3) {
        if(argc != 1){
            fprintf(stderr, "Error: The -L (List) option takes a single argument specifying the chain ID.\n\n");
            usage();        
        }
    } else if(argc == 5 || argc == 6){
        // Parse index
        // TODO5 Sanitize?
        index = atoi(argv[1]);

        // Parse direction
        strncpy(direction_str, argv[2], 4);
        if(strncmp(direction_str, "INC", 4) == 0) {
            direction = IN_RULE;
        } else if (strncmp(direction_str, "OUT", 4) == 0){
            direction = OUT_RULE;
        } else {
            fprintf(stderr, "Error: did not recognize direction \"%s\". Should be either INC or OUT.\n\n",
                            argv[2]);
            usage();
        }

        // Parse action
        strncpy(action_str, argv[3], 7);
        if(strncmp(action_str, "REJECT", 7) == 0) {
            action = DROP_PACKET;
        } else if (strncmp(action_str, "ACCEPT", 7) == 0){
            action = ACCEPT_PACKET;
        } else {
            fprintf(stderr, "Error: did not recognize action \"%s\". Should be either REJECT or ACCEPT.\n\n",
                            argv[3]);
            usage();
        }

        // Parse start address
        if(!inet_pton(AF_INET, argv[4], &start_addr)) {
            fprintf(stderr, "Error: Could not parse start ip \"%s\". Must be a valid ip address.\n\n", argv[2]);
            usage();
        }
        start_addr = htonl(start_addr);

        if(argc == 6){
            // Parse optional end address
            if(!inet_pton(AF_INET, argv[5], &end_addr)) {
                fprintf(stderr, "Error: Could not parse end ip \"%s\". Must be a valid ip address.\n\n", argv[3]);
                usage();
            }
            end_addr = htonl(end_addr);
        }
    } else if (argc < 5){
        fprintf(stderr, "Error: Too few arguments\n\n");
        usage();
    } else {
        fprintf(stderr, "Error: Too many arguments\n\n");
        usage();
    }

    if(start_addr && !end_addr){
        end_addr = start_addr;
    }

    switch (method) {
    case 1:
        fwdec_add_rule(direction, type, action, start_addr, end_addr, port, (char*) name, chain_id, index);
        break;
    case 2:
        fwdec_delete_rule(direction, type, action, start_addr, end_addr, port, (char*) name, chain_id, index);
        break;
    case 3:
        fwdec_list_rules(chain_id);
    default:
        break;
    }
	return EXIT_SUCCESS;
}
