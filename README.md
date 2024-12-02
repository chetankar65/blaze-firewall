# blaze-firewall (still under development)
A simple rudimentary firewall written in C leveraging many networking principles and UNIX libraries. <br>

Commands:
add ACCESS-TYPE [IP/PORT] PROTOCOL: Adds a rule <br>
delete RULE_NO: Deletes a specific rule <br>
update RULE_NO ACCESS-TYPE [IP/PORT] PROTOCOL: Updates a specific rule <br>
list: Lists all rules <br>

Special commands:
add deny *: Allows no connection to system (not done fully) <br>
add allow *: ALlows all connections to system (not done fully) <br>

TODO:
- Prevent connections to a specific port
- Experiment with eBPF (extended Berkely Packet filters) 
- Experiment with other libraries like libnetfilter_queue
- Make the command line more robust and add config files