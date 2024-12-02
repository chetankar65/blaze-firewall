# blaze-firewall
A simple rudimentary firewall written in C leveraging many networking principles and UNIX libraries.

Commands:
add ACCESS-TYPE [IP/PORT] PROTOCOL
delete RULE_NO
update RULE_NO ACCESS-TYPE [IP/PORT] PROTOCOL
list

Special commands:
add deny *
add allow *