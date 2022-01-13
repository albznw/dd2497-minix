#include <sys/fwctl.h>
#include <sys/types.h>
#include <ctype.h>
#include <lib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


enum Method {NO_METHOD = 0, METHOD_ADD = 1, METHOD_DELETE = 2, METHOD_LIST = 3 };

enum PACKET_TYPE { TYPE_IP, TYPE_TCP, TYPE_UDP, TYPE_ICMP, TYPE_RAW, TYPE_END };
char* packet_types[] = { "IP", "TCP", "UDP", "ICMP", "RAW" };

typedef struct firewall_args_type {
    uint32_t start_addr;
    uint32_t end_addr;
    uint16_t port;
    uint8_t method;
    uint8_t direction;
    uint8_t action;
    uint8_t type;
    int index;
    int chain_id;
    uid_t uid; // TODO5: Is this a correct default value?
    char name[16];
} firewall_args_type;



#define	GETOPTSTR	"ADLp:n:t:u:"
static void __dead
usage(void) {
    // TODO5: Update firewall man page
	fprintf(stderr,
	    "usage:\n%s %s\n%s\n%s\n\n%s\n%s\n%s\n",
	    "firewall -A [-p port] [-n pname] [-t IP|TCP|UDP|ICMP|RAW] [-u userID]",
	    "P|G|U index INC|OUT REJECT|ACCEPT start_ip [end_ip]",
        "firewall -D P|G|U index",
        "firewall -L P|G|U",
        "A userID is only used if adding/deleting rules to/from the privileged chain, and in this case it is required.",
        "Specify Privelaged chain (P), Global chain (G) or user chain (U)."
        "If it is not specified it defaults to the calling user.",
        "For more information consult the manual using \"man firewall\"");
	exit(1);
}

void print_method_error() {
    fprintf(stderr, "Error: must choose only one of -A, -D, -L.\n\n");
    usage();
}

int firewall_parse_args(firewall_args_type *fw_args, int argc, char **argv){
    extern char *optarg;
	extern int optind;

    // Initialize everything to zero
    fw_args->method = 0;
    fw_args->uid = NO_USER_ID;
    fw_args->port = 0;

    fw_args->start_addr = 0; fw_args->end_addr = 0;
    fw_args->direction = 0; fw_args->action = 0; fw_args->type = 0;
    fw_args->index = 0;
    fw_args->chain_id = 0; 
    fw_args->name[0] = '\0';

    char chain_str[2]; chain_str[0] = '\0';
    char type_str[5]; type_str[0] = '\0';
    char direction_str[4]; direction_str[0] = '\0';
    char action_str[7]; action_str[0] = '\0';

    uid_t effuid = geteuid();

    // Parse "optional" input arguments
    int argument = getopt(argc, argv, GETOPTSTR);
    while (argument != -1) {
        switch ((char) argument) {
            
            // Parse method
            case 'A':
                if (fw_args->method == NO_METHOD) {
                    fw_args->method = METHOD_ADD;
                } else {
                    print_method_error();
                }
                break;
            
            case 'D':
                if (fw_args->method == NO_METHOD) {
                    fw_args->method = METHOD_DELETE;
                } else {
                    print_method_error();
                }
                break;

            case 'L':
                if (fw_args->method == NO_METHOD) {
                    fw_args->method = METHOD_LIST;
                } else {
                    print_method_error();
                }
                break;
            // End parse method

            // Parse user id
            case 'u':
                // TODO5 Sanitize?
                fw_args->uid = atoi(optarg);
                break;

            // Parse port
            case 'p':
                {
                    char* end;
                    long number = strtoul(optarg, &end, 10);
                    if (*end == '\0' && number < 65536){
                        fw_args->port = number;
                    } else {
                        fprintf(stderr, "Error: invalid port \"%s\", must be 0-65535.\n\n", optarg);
                        usage();
                    }
                }
                break;
            
            // Parse packet type
            case 't':
                strncpy(type_str, optarg, 5);
                for (int type_id = 0; type_id < TYPE_END; type_id++) {
                    if (strncmp(type_str, packet_types[type_id], 5) == 0) {
                        fw_args->type = type_id;
                    }
                    else {
                        fprintf(stderr, "Error: did not recognize protocol type \"%s\". %s\n\n", argv[0], "Should be either IP, TCP, UDP, ICMP or RAW.");
                        usage();
                    }
                }
                break;

            default:
                fprintf(stderr, "Error: unrecognized argument \"-%c\", must be 0-255.\n\n", (char) argument);
                usage();
                break;
        }


        // Load next argument
        argument = getopt(argc, argv, GETOPTSTR);
    }

    argc -= optind;
	argv += optind;

    if(argc == 0) {
        fprintf(stderr, "Error: No required arguments given.\n\n");
        usage();
    }

	// Parse chain id
    // TODO5 Sanitize?
    // Parse direction
    strncpy(chain_str, argv[0], 2);
    if(strncmp(chain_str, "P", 2) == 0) {
        fw_args->chain_id = PRIVILEGED_CHAIN_ID;
    } else if (strncmp(chain_str, "G", 2) == 0){
        fw_args->chain_id = GLOBAL_CHAIN_ID;
    } else if (strncmp(chain_str, "U", 2) == 0){
        fw_args->chain_id = USER_CHAIN_ID;
    } else {
        fprintf(stderr, "Error: did not recognize direction \"%s\". Should be either INC or OUT.\n\n", argv[2]);
        usage();
    }

    if (fw_args->method == NO_METHOD) {
        fprintf(stderr, "Error: No method was specified.\n\n");
        usage();
    }

    if (fw_args->method == METHOD_ADD) {

        // Check that we have the right amount of arguments
        if(!(argc == 5 || argc == 6)) {
            fprintf(stderr, "Error: Wrong number of arguments specified!\n\n");
            usage();
        }

        // If we supply no userID when adding a rule to the privileged chain, we default to the calling user's ID.
        if (fw_args->chain_id == PRIVILEGED_CHAIN_ID && fw_args->uid == NO_USER_ID) {
            fw_args->uid = effuid;
        }

        // If the rule is added to the global chain, the rule should apply to everyone thus set the id to -1
        if (fw_args->chain_id == GLOBAL_CHAIN_ID) {
            fw_args->uid = NO_USER_ID;
        }

        // If the rule is added to the user chain we should use the calling user's id
        if (fw_args->chain_id == USER_CHAIN_ID) {
            if (effuid == 0) {
                if (fw_args->uid == NO_USER_ID) {
                    fw_args->uid = 0;
                    printf("Warn: You can not add a general rule to the user chain. The rule has been added with uid = 0\n\n");
                }
            } else {
                if (!(fw_args->uid == effuid || fw_args->uid == NO_USER_ID)) {
                    printf("Warn: You can not add rules for other users. This rule has been added with uid = %d\n\n", effuid);
                }
                fw_args->uid = effuid;
            }
        }

        // Parse index
        // TODO5 Sanitize?
        fw_args->index = atoi(argv[1]);

        // Parse direction
        strncpy(direction_str, argv[2], 4);
        if(strncmp(direction_str, "INC", 4) == 0) {
            fw_args->direction = IN_RULE;
        } else if (strncmp(direction_str, "OUT", 4) == 0){
            fw_args->direction = OUT_RULE;
        } else {
            fprintf(stderr, "Error: did not recognize direction \"%s\". Should be either INC or OUT.\n\n", argv[2]);
            usage();
        }

        // Parse action
        strncpy(action_str, argv[3], 7);
        if(strncmp(action_str, "REJECT", 7) == 0) {
            fw_args->action = DROP_PACKET;
        } else if (strncmp(action_str, "ACCEPT", 7) == 0){
            fw_args->action = ACCEPT_PACKET;
        } else {
            fprintf(stderr, "Error: did not recognize action \"%s\". Should be either REJECT or ACCEPT.\n\n", argv[3]);
            usage();
        }

        // Parse start address
        if(!inet_pton(AF_INET, argv[4], &(fw_args->start_addr))) {
            fprintf(stderr, "Error: Could not parse start ip \"%s\". Must be a valid ip address.\n\n", argv[4]);
            usage();
        }

        if(argc == 6){
            // Parse optional end address
            if(!inet_pton(AF_INET, argv[5], &(fw_args->end_addr))) {
                fprintf(stderr, "Error: Could not parse end ip \"%s\". Must be a valid ip address.\n\n", argv[5]);
                usage();
            }
        }

        if (fw_args->start_addr && !fw_args->end_addr) {
            fw_args->end_addr = fw_args->start_addr;
        }

    } else if(fw_args->method == METHOD_DELETE) {
        if(argc != 2){
            fprintf(stderr, "Error: The -D (Delete) option takes two arguments specifying the chain ID and the index.\n\n");
            usage();        
        }

        // Parse index
        // TODO5 Sanitize?
        fw_args->index = atoi(argv[1]);
    } else if(fw_args->method == METHOD_LIST) {
        if(argc != 1){
            fprintf(stderr, "Error: The -L (List) option takes a single argument specifying the chain ID.\n\n");
            usage();        
        }
    }
    
    return 1;
}

int main(int argc, char **argv) {
    firewall_args_type fw_args;
    firewall_parse_args(&fw_args, argc, argv);

    extern char *optarg;
	extern int optind;

    // Does user have permission?
    if (fw_args.chain_id != USER_CHAIN_ID) {
        if (geteuid() != 0) {
            fprintf(stderr, "Need root permissions to view or edit firewall rules.\n");
            exit(1);
        }
    }
    
    // Check what chain
    switch (fw_args.method) {
    case METHOD_ADD:
        fwdec_add_rule(
            fw_args.direction,
            fw_args.type,
            fw_args.action,
            fw_args.start_addr,
            fw_args.end_addr,
            fw_args.port,
            fw_args.name, // (char*) fw_args.name,
            fw_args.chain_id,
            fw_args.index,
            fw_args.uid);
        break;

    case METHOD_DELETE:
        fwdec_delete_rule(fw_args.chain_id, fw_args.index);
        break;

    case METHOD_LIST:
        fwdec_list_rules(fw_args.chain_id);
        break;
    
    default:
        break;
    }

	return EXIT_SUCCESS;
}
