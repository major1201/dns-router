#! /usr/bin/env python
# encoding: utf-8
from __future__ import division, absolute_import, with_statement, print_function
import os
import time
import re

from dnslib import DNSLabel
from dnslib.server import DNSLogger
from dnslib.server import BaseResolver

REG_IP = "^(([2][5][0-5]|[2][0-4][0-9]|[1][0-9]{2}|[1-9][0-9]|[0-9])[.]){3}([2][5][0-5]|[2][0-4][0-9]|[1][0-9]{2}|[1-9][0-9]|[0-9])$"


def log(s):
    from datetime import datetime
    print(datetime.now().strftime("[%Y-%m-%d %X] ") + s)


class RouterResolver(BaseResolver):
    def __init__(self, server):
        self.server = server
        self.rule = server.rule

    def resolve(self, request, handler):
        import socket
        from dnslib import DNSRecord
        from dnslib.server import DNSHandler
        from dnslib import RCODE
        from dnslib import RR
        from dnslib import QTYPE
        from dnslib import A

        assert isinstance(request, DNSRecord)
        assert isinstance(handler, DNSHandler)
        qname = request.q.get_qname()
        log_arr = [
            self.server.protocol + "://" + self.server.listen_addr + ":" + str(self.server.port), "<-",
            handler.client_address[0] + ":" + str(handler.client_address[1]) + ",",
            str(qname), "/", QTYPE[request.q.qtype], "-->"
        ]
        try:
            if qname.label in self.rule.host_table and request.q.qtype == QTYPE.A:
                # find host table
                reply = request.reply()
                host_addr = self.rule.host_table[qname.label]
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(host_addr), ttl=60))

                log_arr.append("HOST:")
                log_arr.append(host_addr)
                log(" ".join(log_arr))
                return reply
            else:
                # route dns servers by domain
                for domain in self.rule.domain_map:
                    if qname.label[-len(domain.label):] == domain.label:  # match suffix or not
                        ptserver = self.rule.domain_map[domain]

                        log_arr.append("PASSED THROUGH:")
                        log_arr.append(ptserver.protocol + "://" + ptserver.addr + ":" + str(ptserver.port))
                        log(" ".join(log_arr))

                        proxy_r = request.send(ptserver.addr, ptserver.port, tcp=ptserver.protocol == "tcp", timeout=ptserver.timeout)
                        reply = DNSRecord.parse(proxy_r)
                        return reply

                # pass through default dns server
                ddserver = self.rule.default_dns_server

                log_arr.append("PASSED DEFAULT:")
                log_arr.append(ddserver.protocol + "://" + ddserver.addr + ":" + str(ddserver.port))
                log(" ".join(log_arr))

                proxy_r = request.send(ddserver.addr, ddserver.port, tcp=ddserver.protocol == "tcp", timeout=ddserver.timeout)
                reply = DNSRecord.parse(proxy_r)
        except socket.timeout:
            log_arr.append("-->")
            log_arr.append("TIMEOUT")

            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        return reply


class EmptyDNSLogger(DNSLogger):
    def log_prefix(self, handler):
        if self.prefix:
            return "[%s] " % (time.strftime("%Y-%m-%d %X"))
        else:
            return ""

    def log_recv(self, handler, data):
        pass

    def log_send(self, handler, data):
        pass

    def log_request(self, handler, request):
        pass

    def log_reply(self, handler, reply):
        pass

    def log_truncated(self, handler, reply):
        pass

    def log_error(self, handler, e):
        pass

    def log_data(self, dnsobj):
        pass


class ConfigParser:
    def __init__(self, config_path):
        import yaml
        self.raw_config = yaml.load(open(config_path))
        self.pass_through_dns_servers = {}
        self.host_tables = {}
        self.domain_lists = {}
        self.rules = {}
        self.local_dns_servers = []
        self._parse_pass_through_dns_servers()
        self._parse_host_tables()
        self._parse_domain_lists()
        self._parse_rules()
        self._parse_local_dns_servers()

    def _parse_pass_through_dns_servers(self):
        if "pass_through_dns_servers" in self.raw_config:
            for key, val in self.raw_config.get("pass_through_dns_servers").items():
                self.pass_through_dns_servers[key] = PassThroughServer(val)

    def _parse_host_tables(self):
        if "host_tables" in self.raw_config:
            for key, val in self.raw_config.get("host_tables").items():
                assert isinstance(val, dict)
                self.host_tables[key] = dict((DNSLabel(k), v) for k, v in val.items())

    def _parse_domain_lists(self):
        if "domain_lists" in self.raw_config:
            for key, val in self.raw_config.get("domain_lists").items():
                assert isinstance(val, list)
                self.domain_lists[key] = [DNSLabel(l) for l in val]

    def _parse_rules(self):
        if "rules" in self.raw_config:
            for key, val in self.raw_config.get("rules").items():
                assert isinstance(val, dict)
                self.rules[key] = Rule(val, self)

    def _parse_local_dns_servers(self):
        assert "local_dns_servers" in self.raw_config
        assert isinstance(self.raw_config["local_dns_servers"], list)
        assert len(self.raw_config["local_dns_servers"]) > 0
        for local_server in self.raw_config["local_dns_servers"]:
            self.local_dns_servers.append(LocalServer(local_server, self))


class LocalServer:
    def __init__(self, server, parser):
        assert isinstance(server, dict)
        assert "rule" in server
        self.protocol = server.get("protocol", "udp")
        assert self.protocol in ("udp", "tcp")
        self.listen_addr = server.get("listen_addr", "127.0.0.1")
        assert re.match(REG_IP, self.listen_addr)
        self.port = server.get("port", 53)
        assert isinstance(self.port, int)
        rule = server.get("rule")
        if isinstance(rule, str):
            assert rule in parser.rules
            self.rule = parser.rules.get(rule)
        else:
            self.rule = Rule(server.get("rule"), parser)

    def get_protocol(self):
        return self.protocol

    def get_listen_addr(self):
        return self.listen_addr

    def get_port(self):
        return self.port

    def get_rule(self):
        return self.rule


class Rule:
    def __init__(self, rule, parser):
        assert isinstance(rule, dict)

        # process rule_dict
        # default_dns_server
        assert "default_dns_server" in rule
        default_dns_server = rule.get("default_dns_server")
        if isinstance(default_dns_server, str):
            assert default_dns_server in parser.pass_through_dns_servers
            self.default_dns_server = parser.pass_through_dns_servers.get(default_dns_server)
        else:
            self.default_dns_server = PassThroughServer(default_dns_server)
        # host table
        host_table = rule.get("host_table", {})
        if isinstance(host_table, str):
            assert host_table in parser.host_tables
            host_table = parser.host_tables.get(host_table)
        else:
            assert isinstance(host_table, dict)
            host_table = dict((DNSLabel(k), v) for k, v in host_table.items())
        self.host_table = host_table
        assert isinstance(self.host_table, dict)

        # domain list
        self.domain_map = {}
        for ptserver, val in rule.items():
            if ptserver not in ("default_dns_server", "host_table"):
                assert ptserver in parser.pass_through_dns_servers
                ptserver_obj = parser.pass_through_dns_servers[ptserver]
                if isinstance(val, str):
                    assert val in parser.domain_lists
                    domain_list = parser.domain_lists[val]
                else:
                    assert isinstance(val, list)
                    domain_list = [DNSLabel(l) for l in val]
                for domain in domain_list:
                    self.domain_map[domain] = ptserver_obj

    def get_default_dns_server(self):
        return self.default_dns_server

    def get_host_table(self):
        return self.host_table

    def get_domain_map(self):
        return self.domain_map


class PassThroughServer:
    def __init__(self, ptserver):
        assert isinstance(ptserver, dict)
        assert "addr" in ptserver
        self.addr = ptserver.get("addr")
        assert re.match(REG_IP, self.addr)
        self.port = ptserver.get("port", 53)
        assert isinstance(self.port, int)
        self.protocol = ptserver.get("protocol", "udp")
        assert self.protocol in ("udp", "tcp")
        self.timeout = ptserver.get("timeout", 5)
        assert isinstance(self.timeout, int)

    def get_addr(self):
        return self.addr

    def get_port(self):
        return self.port

    def get_protocol(self):
        return self.protocol

    def get_timeout(self):
        return self.timeout


if __name__ == "__main__":
    import sys
    from dnslib.server import DNSServer

    config = ConfigParser(os.path.join(os.path.dirname(__file__), "dns-router.yml"))

    servers = []
    for _local_server in config.local_dns_servers:
        assert isinstance(_local_server, LocalServer)
        resolver = RouterResolver(_local_server)
        logger = EmptyDNSLogger()
        _server = DNSServer(resolver, address=_local_server.listen_addr, port=_local_server.port, tcp=_local_server.protocol == "tcp", logger=logger)
        _server.start_thread()
        servers.append(_server)
        log("Started local DNS server: " + _local_server.listen_addr + ":" + str(_local_server.port) + " (" + _local_server.protocol + ")")

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        for _s in servers:
            try:
                _s.stop()
            except Exception:
                pass
