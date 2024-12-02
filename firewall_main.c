#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "firewall_rules.h"

#define BUFFER_SIZE 1024
#define MAXARGS 10

int is_ip(char* ip_or_port) {
    char* ptr = ip_or_port;
    while (*ptr != '\0') {
        if ((*ptr) == '.') return 1;
        ptr++;
    }

    return 0;
}

Access map_access(char* access) {
    Access type;
    if (strncmp(access, "allow", 5) == 0) {
        type = ALLOW; 
    } else if (strncmp(access, "deny", 4) == 0) {
        type = DENY;
    } else {
        printf("Incorrent format.\n");
        exit(1);
    }

    return type;
}

Protocol map_protocol(char* protocol) {
    Protocol proto;
    if (strncmp(protocol, "IP", 2) == 0) {
        proto = IP; 
    } else if (strncmp(protocol, "ICMP", 4) == 0) {
        proto = ICMP;
    } else {
        printf("Incorrent format.\n");
        exit(1);
    }

    return proto;
}

void tokenize(char* input_buf) {
    char* command;
    char* token;
    char delimiter[] = " ";
    token = strtok(input_buf, delimiter);
    command = token;

    char* args[MAXARGS];
    int arg_count = 0;
    if (strncmp(command, "add", 3) == 0) {
        token = strtok(NULL, delimiter);
        while (token) {
            args[arg_count++] = token;
            token = strtok(NULL, delimiter);
        }

        //Rule rule = {ALLOW, "192.168.1.1", htons(80), IP};
        char* access;
        char* ip_or_port;
        char* protocol;
        access = args[0];
        ip_or_port = args[1];
        protocol = args[2];
        Access type;
        Protocol ptype;

        //Rule rule;

        if (is_ip(ip_or_port)) {
            Rule rule;
            rule.type = map_access(access);
            rule.portno = -1;
            rule.proto = map_protocol(protocol);
            strcpy(rule.ip_addr, ip_or_port);
            add_rule(rule, 1);
            printf("Added a new rule.\n");
        }

    }

}

int main() {
    //Rule rule = {ALLOW, "192.168.1.1", htons(80), IP};
    //add_rule(rule); 
    printf("Welcome to blaze firewall\n"); 
    printf("Input format: ACTION ACCESS-TYPE [IP/PORT] PROTOCOL\n");
    /*
    command structure
    add ACCESS-TYPE [IP/PORT] PROTOCOL
    delete [IP/PORT] PROTOCOL
    update ACCESS-TYPE [IP/PORT] PROTOCOL
    list
    */
    read_rules(); 
    print_all_rules();
    char buffer[BUFFER_SIZE];

    while (1) {
        printf("$> ");
        fgets(buffer, BUFFER_SIZE, stdin);
        tokenize(buffer);
        read_rules(); 
        print_all_rules();
    }
}