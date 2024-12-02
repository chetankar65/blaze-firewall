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
        return "ACCEPT";
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

void freeAll() {
    for (int i = 0; i < rule_count; i++) {
        if (all_rules[i]) free(all_rules[i]);
    }
}

void deserialize_rule(int fd, Rule *rule) {
    freeAll(); // manage some memory
    // this method is not optimized at all, but for less rules it is acceptable
    rule_count = 0;
    while (1) {
        Rule *new_rule = (Rule *)malloc(sizeof(Rule));
        if (!new_rule) {
            perror("malloc");
            break;
        }

        ssize_t bytes_read = read(fd, new_rule, sizeof(Rule));
        if (bytes_read == 0) {
            free(new_rule);
            break;
        } else if (bytes_read < 0) {
            perror("read");
            free(new_rule);
            break;
        }

        if (rule_count < MAXRULES) {
            all_rules[rule_count++] = new_rule;
        } else {
            printf("Max rule limit reached, cannot add more rules.\n");
            free(new_rule);
            break;
        }
    }
}

void print_all_rules() {
    for (int i = 0; i < rule_count; i++) {
        Rule* rule = all_rules[i];
        if (!rule) continue;
        printf("%d. ", i);
        printf("Access: %s |", (rule->type == ALLOW) ? "ALLOW" : "DENY");
        printf(" IP Address: %s |", rule->ip_addr);
        printf(" Port: %d |", rule->portno);
        printf(" Protocol: %s \n", (rule->proto == IP) ? "IP" : "ICMP");
    }
}

void add_rule(Rule rule, int ip) {
    //Rule rule = {ALLOW, "192.168.1.1", htons(80), IP};
    int fd = open("rules.dat",  O_WRONLY | O_CREAT | O_APPEND, 0644);

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

int update_rule(Rule rule, int rule_no, int ip) {
    // all rules are already brought into memory
    for (int i = 0; i < rule_count; i++) {
        if (rule_no == (i + 1)) {
            char full_command[CMD_SIZE];            
            sprintf(full_command, "sudo iptables -D INPUT -s %s -p %s -j %s", all_rules[i]->ip_addr, rev_map_protocol(all_rules[i]->proto), rev_map_access(all_rules[i]->type));
            int ret = system(full_command);
            all_rules[i] = &rule;
            add_rule(rule, ip);
            return 0;
        }
    }

    return 1;
}

void rewrite() {
    int fd = open("rules.dat", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        return;
    }

    for (int i = 0; i < rule_count; i++) {
        if (all_rules[i] != NULL) {
            if (write(fd, all_rules[i], sizeof(Rule)) == -1) {
                perror("write");
                close(fd);
                return;
            }
        }
    }

    close(fd);
    printf("Rules file updated successfully.\n");
}

int delete_rule(int rule_no) {
    int k;
    for (int i = 0; i < rule_count; i++) {
        if (rule_no == (i + 1)) {
            char full_command[CMD_SIZE];            
            sprintf(full_command, "sudo iptables -D INPUT -s %s -p %s -j %s", all_rules[i]->ip_addr, rev_map_protocol(all_rules[i]->proto), rev_map_access(all_rules[i]->type));
            int ret = system(full_command);
            all_rules[i] = NULL;
            k = i;
            break;
        }
    }

    if (k >= rule_count) return 1;

    // shift the array
    for (int i = k; i < rule_count; i++) {
        all_rules[i] = all_rules[i + 1];
    }

    rule_count--;
    rewrite();
    /// overwrite the file with updated rules
    return 0;
}

