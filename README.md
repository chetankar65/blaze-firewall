# blaze-firewall (still under development)
A simple rudimentary firewall written in C leveraging many networking principles and UNIX libraries. <br>

Commands:
<code>add ACCESS-TYPE [IP/PORT] PROTOCOL</code>: Adds a rule <br>
<code>delete RULE_NO</code>: Deletes a specific rule <br>
<code>update RULE_NO ACCESS-TYPE [IP/PORT] PROTOCOL </code>: Updates a specific rule <br>
<code>list</code>: Lists all rules <br>
<code>exit</code>: Exists the service <br>

Special commands:
add deny *: Allows no connection to system (not done fully) <br>
add allow *: ALlows all connections to system (not done fully) <br>

TODO:
- Prevent connections to a specific port
- Experiment with eBPF (extended Berkely Packet filters) 
- Experiment with other libraries like libnetfilter_queue
- Make the command line more robust and add config files