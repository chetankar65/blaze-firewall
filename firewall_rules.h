#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAXRULES 50
#define IPFIELDLEN 16
#define CMD_SIZE 1024

typedef enum Access {ALLOW, DENY} Access;
typedef enum Protocol {IP, ICMP} Protocol;

typedef struct Rule {
    Access type; // allow/ deny connections
    char ip_addr[IPFIELDLEN]; // ip address
    int portno; // port number for corresponding rule
    Protocol proto; /// what type of protocol to apply target
} Rule;

Rule* all_rules[MAXRULES];
int rule_count = 0;

char* rev_map_protocol(Protocol type) {
    if (type == IP) {
        return "ip";
    } else if (type == ICMP) {
        return "icmp";
    }
}

char* rev_map_access(Access type) {
    if (type == ALLOW) {
        return "ALLOW";
    } else if (type == DENY) {
        return "DROP";
    }
}

void serialize_rule(int fd, Rule *rule, int ip) {
    if (write(fd, rule, sizeof(Rule)) == -1) {
        perror("write");
    } else {
        //printf("Rule serialized successfully.\n");
        if (ip) {
            /// adding a rule for a particular IP. If its 0, means we are 
            /// doing for port
            char full_command[CMD_SIZE];
            // iptables -A INPUT -s 127.0.0.1 -p icmp -j DROP
            
            sprintf(full_command, "sudo iptables -A INPUT -s %s -p %s -j %s", rule->ip_addr, rev_map_protocol(rule->proto), rev_map_access(rule->type));
            int ret = system(full_command);
            if (ret == 0) printf("Success\n");
            else printf("Some error!\n");
        }
    }
}

void deserialize_rule(int fd, Rule *rule) {
    while (read(fd, rule, sizeof(Rule)) > 0) {
        all_rules[rule_count++] = rule;
    }
}

void print_all_rules() {
    for (int i = 0; i < rule_count; i++) {
        Rule* rule = all_rules[i];
        if (!rule) continue;
        printf("1. ");
        printf("Access: %s |", (rule->type == ALLOW) ? "ALLOW" : "DENY");
        printf(" IP Address: %s |", rule->ip_addr);
        printf(" Port: %d |", rule->portno);
        printf(" Protocol: %s \n", (rule->proto == IP) ? "IP" : "ICMP");
    }
}

void add_rule(Rule rule, int ip) {
    //Rule rule = {ALLOW, "192.168.1.1", htons(80), IP};
    int fd = open("rules.dat",  O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd == -1) {
        perror("open");
        return;
    }

    serialize_rule(fd, &rule, ip);
    close(fd);
}

void read_rules() {
    Rule rule;

    int fd = open("rules.dat", O_RDONLY | O_CREAT, 0664);
    if (fd == -1) {
        perror("open");
        return;
    }

    deserialize_rule(fd, &rule);
    close(fd);
}

void update_rule(Rule rule) {
    // all rules are already brought into memory
    for (int i = 0; i < rule_count; i++) {
        
    }
}

void delete_rule() {

}
