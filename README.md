# dns-router

- Author: major1201
- Current version: 0.1

## Summary

A simple DNS server which can shunt your DNS requests towards different DNS servers.

## Configuration

- Configure local DNS servers node:
```
local_dns_servers:
  - protocol: udp             # optional, "udp", "tcp", default: "udp"
    listen_addr: 127.0.0.1    # optional, default: 127.0.0.1
    port: 53                  # optional, default: 53
    rule: my_rule1            # required, it links to the "rules" node
  - protocol: tcp
    listen_addr: 127.0.0.1
    port: 53
    rule: my_rule2
```

- Configure rules node:
```
rules:
  my_rule1:                                    # required, define your own rule name
    default_dns_server: my_default_server1     # required, it links to the "pass_through_dns_servers" node
    host_table: my_host_table1                 # optional, default: empty table. it links to the "host_tables" node
    my_main_server: my_domain_list1            # optional, domains in "my_domain_list1" which links to "domain_lists node"
                                               # would be resolved through "my_main_server"
    my_backup_server:                          # you could also write your domain list under the server node
      - google.com
      - youtube.com
    my_third_server:
    ...
  rule2:
    default_dns_server: my_default_server2
    host_table:                                # you could also define your host table just under this node
      www.example.com: 1.2.3.4
      www.example.net: 2.3.4.5
    my_main_server: my_domain_list2
    my_backup_server:
      - twitter.com
```

- Configure pass through DNS servers:
```
pass_through_dns_servers:
  my_default_server1:   # required, define your own pass through server name
    addr: 8.8.8.8       # required, IP address of your server
    port: 53            # optional, default: 53
    protocol: udp       # optional, "udp", "tcp", default: "udp"
    timeout: 5          # optional, default: 5 (seconds)
  my_default_server2:
    addr: 8.8.4.4
    protocol: tcp
  my_main_server:
    addr: 209.244.0.3
  my_backup_server:
    addr: 209.244.0.4
    timeout: 10
```

- Configure host tables:
```
host_tables:
  my_host_table1:                # required: define your own host table name
    www.instagram.com: 127.0.0.1 # host rule in key, value format
    www.example.com: 12.34.56.78
  my_host_table2:
  ...
```

- Configure domain list:
```
domain_lists:
  my_domain_list1:         # required: define your own domain list name
    - domain1              # domain will match the request domain's suffix
    - domain2
  my_domain_list2:
    - domain3
    - domain4
```

## Requirements

- dnslib `pip install dnslib`
- pyyaml `pip install pyyaml`

## License

This project follows GNU General Public License v3.0.
