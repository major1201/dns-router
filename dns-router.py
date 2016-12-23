#! /usr/bin/env python
# encoding: utf-8
from __future__ import division, absolute_import, with_statement, print_function
import sys
import os
import time
import re
import six
from collections import Iterable
from utils import strings, num
from future.moves.urllib.parse import urlparse

import dnslib
from dnslib import DNSLabel
from dnslib.server import DNSLogger
from dnslib.server import BaseResolver
from dnslib.server import DNSServer

PROJ = 'dns-router'
LOGGER_NAME = 'DNS'


class ArgumentParser(object):
    args = None

    @staticmethod
    def parse():
        import argparse
        parser = argparse.ArgumentParser(prog=PROJ,
                                         description='A simple dns router', formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2a')
        parser.add_argument('-c', '--config', dest='config', default=os.path.join(os.path.dirname(__file__), PROJ + '.yml'), help='specify the config file, default: ' + PROJ + '.yml')
        parser.add_argument('-t', '--test', dest='test', action='store_true', help='test the format of the config file')
        ArgumentParser.args = parser.parse_args().__dict__


class ConfigParser:
    DNSURL_REGEX = '^(udp|tcp)://' + strings.REG_IP[1:-1] + '(:\d{2,5})?$'

    def __init__(self, conf):
        self.conf = conf

    def check(self):
        dns_servers = self.conf.get('dns_servers', [])
        if not isinstance(dns_servers, Iterable):
            raise ValueError('dns_servers should be an array')
        for server in dns_servers:
            self.check_server(server)

    def check_server(self, server):
        if 'url' not in server:
            raise ValueError('"url" field expected!')
        url = server['url']
        if not re.match(self.DNSURL_REGEX, url):
            raise ValueError('"url" field format error!')

        if 'rules' not in server:
            raise ValueError('"rules" field expected!')
        rules = server['rules']
        if not isinstance(rules, Iterable):
            raise ValueError('rules should be an array')
        for rule in rules:
            self.check_rule(rule)

    def check_rule(self, rule):
        if 'type' not in rule:
            raise ValueError('"type" field expected!')
        rtype = rule['type']
        if rtype != 'REJECT':
            if 'value' not in rule:
                raise ValueError('"value" field expected!')
        rvalue = rule.get('value', None)
        if rtype == 'FORWARD':
            if not re.match(self.DNSURL_REGEX, rvalue):
                raise ValueError('"FORWARD" value format error: ' + str(rvalue))
        elif rtype == 'REJECT':
            pass
        elif rtype in ('A', 'CNAME', 'MX', 'NS', 'PTR', 'AAAA', 'SRV', 'SOA'):
            if isinstance(rvalue, six.string_types):
                self.check_value(rtype, rvalue)
            elif isinstance(rvalue, Iterable):
                for item in rvalue:
                    self.check_value(rtype, item)
            else:
                raise ValueError('Value should be a string or an array.')
        else:
            raise ValueError('"type" should be in ("FORWARD", "REJECT", "A", "CNAME", "MX", "NS", "PTR", "AAAA", "SRV", "SOA")')

        if 'domain' not in rule:
            raise ValueError('"domain" field expected!')
        if 'domain-type' not in rule:
            raise ValueError('"domain-type" field expected!')
        rdtype = rule['domain-type']
        if rdtype not in ('FQDN', 'PREFIX', 'SUFFIX', 'KEYWORD', 'WILDCARD', 'REGEX'):
            raise ValueError('Unsupported domain-type: ' + rdtype)

    def check_value(self, rtype, rvalue):
        if not isinstance(rvalue, six.string_types):
            raise ValueError('value error, string expected')
        if rtype == 'A':
            # check ip
            if not re.match(strings.REG_IP, rvalue):
                raise ValueError('"' + rtype + '" value format error: ' + rvalue + ', IP expect.')
        elif rtype in ('CNAME', 'MX', 'NS', 'PTR'):
            # check domain
            if not re.match(strings.REG_DOMAIN, rvalue):
                raise ValueError('"' + rtype + '" value format error: ' + rvalue + ', domain expect.')
        elif rtype == 'AAAA':
            # check ipv6
            if not self._check_ipv6(rvalue):
                raise ValueError('"AAAA" value format error: ' + rvalue)
        elif rtype == 'SRV':
            # check srv
            if not self._check_srv(rvalue):
                raise ValueError('"SRV" value format error: "' + rvalue + '"')
        elif rtype == 'SOA':
            # check soa
            if not self._check_soa(rvalue):
                raise ValueError('"SOA" value format error: "' + rvalue + '"')

    @staticmethod
    def _check_ipv6(ipv6):
        import dnslib.dns
        try:
            ip6_tuple = dnslib.dns._parse_ipv6(ipv6)
            if len(ip6_tuple) == 16:
                flag = True
                for nu in ip6_tuple:
                    if not (0 <= nu <= 255):
                        flag = False
                return flag
        except:
            pass
        return False

    @staticmethod
    def _check_srv(srv):
        arr = srv.split(' ')
        for i in range(3):
            nu = num.safe_int(arr[i])
            if str(nu) != arr[i]:
                return False
            if nu < 0:
                return False
        port = num.safe_int(arr[2])
        if 1 < port < 65535:
            return re.match(strings.REG_DOMAIN, arr[3])
        return False

    @staticmethod
    def _check_soa(soa):
        arr = soa.split(' ')
        for i in range(2, 7):
            nu = num.safe_int(arr[i])
            if str(nu) != arr[i]:
                return False
            if nu < 0:
                return False
        return re.match(strings.REG_DOMAIN, arr[0]) and re.match(strings.REG_DOMAIN, arr[1])


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


class RouterResolver(BaseResolver):
    def __init__(self, server):
        self.server = server
        self.rules = server['rules']

    def resolve(self, request, handler):
        import socket
        from fnmatch import fnmatch
        from dnslib import DNSRecord
        from dnslib.server import DNSHandler
        from dnslib import RR
        from dnslib import QTYPE
        from utils import logger, setting
        import memcache
        import base64

        # initialize memcached
        set_cache = setting.conf.get('cache', {})
        cache_enable = set_cache.get('enable', False)
        cache_addr = set_cache.get('memcached_addr', None)
        cache_client = memcache.Client([cache_addr]) if cache_enable else None

        assert isinstance(request, DNSRecord)
        assert isinstance(handler, DNSHandler)
        qname = request.q.get_qname()
        sqname = str(qname).rstrip('.')
        log_arr = [
            self.server['url'], "<-", handler.client_address[0] + ":" + str(handler.client_address[1]) + ",",
            sqname, "/", QTYPE[request.q.qtype], "-->"
        ]
        reply = None
        for rule in self.rules:
            domain_type = rule['domain-type']
            domain = rule['domain']
            match = False

            if domain_type == 'FQDN':
                match = rule['domain'] == qname.label
            elif domain_type == 'PREFIX':
                match = qname.label[:len(domain.label)] == domain.label
            elif domain_type == 'SUFFIX':
                match = qname.label[-len(domain.label):] == domain.label
            elif domain_type == 'KEYWORD':
                match = sqname.find(domain) >= 0
            elif domain_type == 'WILDCARD':
                match = fnmatch('.' + sqname, domain)
            elif domain_type == 'REGEX':
                match = re.match(domain, sqname)
            if match:
                rtype = rule['type']
                rvalue = rule.get('value', None)
                pvalue = rule.get('pvalue', None)
                if rtype == 'FORWARD':
                    log_arr.append('FORWARD:')
                    log_arr.append(pvalue['url'])
                    cache_key = str(request.q.qtype) + '|' + sqname
                    if cache_enable:
                        cache_value = cache_client.get(cache_key)
                        if cache_value:
                            reply = DNSRecord.parse(base64.decodestring(cache_value))
                            log_arr.append('CACHE')
                            break
                    try:
                        proxy_r = request.send(pvalue['hostname'], pvalue['port'], tcp=pvalue['scheme'] == 'tcp', timeout=5)
                        reply = DNSRecord.parse(proxy_r)
                        if cache_enable:
                            try:
                                # get min ttl
                                ttls = [rr_item.ttl for rr_item in reply.rr]
                                ttl = 60 if len(ttls) == 0 else min(ttls)
                                ttl = 1 if ttl == 0 else ttl
                                cache_client.set(cache_key, base64.encodestring(proxy_r), ttl)
                                log_arr.append('ttl=' + str(ttl))
                            except:
                                logger.error('CACHE ERROR', LOGGER_NAME)
                                logger.error_traceback(LOGGER_NAME)
                    except socket.timeout:
                        log_arr.append('TIMEOUT')
                    break
                elif rtype == 'REJECT':
                    log_arr.append('REJECT')
                    reply = self.gen_nxdomain_reply(request)
                    break
                elif rtype in ('A', 'CNAME', 'MX', 'NS', 'PTR', 'AAAA', 'SRV', 'SOA') and request.q.qtype == getattr(QTYPE, rtype):
                    reply = request.reply()
                    for item in pvalue:
                        reply.add_answer(RR(qname, getattr(QTYPE, rtype), rdata=item, ttl=60))
                    log_arr.append(rtype + ':')
                    log_arr.append(','.join(rvalue))
                    break
        if reply is None:
            log_arr.append('REJECT')
            reply = self.gen_nxdomain_reply(request)
        logger.info(' '.join(log_arr), LOGGER_NAME)
        return reply

    @staticmethod
    def gen_nxdomain_reply(request):
        from dnslib import RCODE

        reply = request.reply()
        reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
        return reply


class DNSServerLoader(object):
    servers = []
    flag = 1  # 0: nothing, 1:start, 2: stop, 3: reload

    @classmethod
    def stop(cls):
        cls.flag = 2

    @classmethod
    def reload(cls):
        cls.flag = 3

    @classmethod
    def _reload(cls, first_run=False):
        from utils import setting, logger

        # restart threads
        dns_servers = cls.parse_server_config(setting.conf)
        for server in dns_servers:
            resolver = RouterResolver(server)
            empty_logger = EmptyDNSLogger()
            _server = DNSServer(resolver, address=server['hostname'], port=server['port'],
                                tcp=server['scheme'] == "tcp", logger=empty_logger)
            _server.start_thread()
            cls.servers.append(_server)
            if not first_run:
                logger.info('Config file reloaded: ' + ArgumentParser.args['config'])
            logger.info('Started local DNS server: ' + server['url'], LOGGER_NAME)

    @classmethod
    def daemon(cls):
        from utils import logger, setting

        try:
            while 1:
                if cls.flag == 0:  # nothing
                    time.sleep(1)
                elif cls.flag == 1:  # start
                    cls.flag = 0
                    cls._reload(first_run=True)
                elif cls.flag == 2:  # stop
                    cls._stop_servers()
                    break
                elif cls.flag == 3:  # reload
                    cls.flag = 0
                    try:
                        # reload settings
                        with open(ArgumentParser.args['config']) as _f:
                            setting.load(_f)
                        ConfigParser(setting.conf).check()
                        cls._stop_servers()
                        cls._reload()
                    except:
                        logger.error_traceback(LOGGER_NAME)
                        logger.error('Config file(' + ArgumentParser.args['config'] + ') checked failed, not reloaded.', LOGGER_NAME)
                sys.stderr.flush()
                sys.stdout.flush()
        except KeyboardInterrupt:
            pass
        finally:
            cls._stop_servers()

    @classmethod
    def _stop_servers(cls):
        from utils import logger

        # stop running threads
        for server in cls.servers:
            assert isinstance(server, DNSServer)
            try:
                server.stop()
                del server
            except:
                logger.error_traceback(LOGGER_NAME)

    @staticmethod
    def parse_server_config(server_config):
        import copy

        _server_config = copy.deepcopy(server_config)
        dns_servers = _server_config.get('dns_servers', [])
        for server in dns_servers:
            # parse url
            scheme, hostname, port = DNSServerLoader.parse_url(server['url'])
            server['scheme'] = scheme
            server['hostname'] = hostname
            server['port'] = port

            # parse rules
            for rule in server['rules']:
                rtype = rule['type']
                if rule['domain-type'] in ('FQDN', 'PREFIX', 'SUFFIX'):
                    rule['domain'] = DNSLabel(rule['domain'])
                if rtype == 'FORWARD':
                    _scheme, _hostname, _port = DNSServerLoader.parse_url(rule['value'])
                    rule['pvalue'] = {
                        'scheme': _scheme,
                        'hostname': _hostname,
                        'port': _port,
                        'url': _scheme + '://' + _hostname + ':' + str(_port)
                    }
                elif rtype in ('A', 'CNAME', 'MX', 'NS', 'PTR', 'AAAA', 'SRV', 'SOA'):
                    if isinstance(rule['value'], six.string_types):
                        rule['value'] = [rule['value']]
                    if rtype == 'A':
                        rule['pvalue'] = [dnslib.A(item) for item in rule['value']]
                    elif rtype == 'CNAME':
                        rule['pvalue'] = [dnslib.CNAME(DNSLabel(item)) for item in rule['value']]
                    elif rtype == 'MX':
                        rule['pvalue'] = [dnslib.MX(DNSLabel(item)) for item in rule['value']]
                    elif rtype == 'NS':
                        rule['pvalue'] = [dnslib.NS(DNSLabel(item)) for item in rule['value']]
                    elif rtype == 'PTR':
                        rule['pvalue'] = [dnslib.PTR(DNSLabel(item)) for item in rule['value']]
                    elif rtype == 'AAAA':
                        rule['pvalue'] = [dnslib.AAAA(item) for item in rule['value']]
                    elif rtype == 'SRV':
                        srv_arr = []
                        for item in rule['value']:
                            item_arr = item.split(' ')
                            srv_arr.append(dnslib.SRV(
                                priority=num.safe_int(item_arr[0]),
                                weight=num.safe_int(item_arr[1]),
                                port=num.safe_int(item_arr[2]),
                                target=item_arr[3]))
                        rule['pvalue'] = srv_arr
                    elif rtype == 'SOA':
                        soa_arr = []
                        for item in rule['value']:
                            item_arr = item.split(' ')
                            soa_arr.append(dnslib.SOA(
                                mname=DNSLabel(item_arr[0]),
                                rname=DNSLabel(item_arr[1]),
                                times=(num.safe_int(t) for t in item_arr[2:])  # serial, refresh, retry, expire, minimun
                            ))
                        rule['pvalue'] = soa_arr
        return dns_servers

    @staticmethod
    def parse_url(url):
        up = urlparse(url)
        upport = up.port
        port = upport if upport else 53
        return up.scheme, up.hostname, port


def start():
    import os.path

    # parse argument
    ArgumentParser.parse()

    # init setting
    from utils import setting
    with open(ArgumentParser.args['config']) as _f:
        setting.load(_f)

    # init logger
    from utils import logger
    logger.initialize()

    # pid file
    if not ArgumentParser.args['test']:
        with open(os.path.join(os.path.dirname(__file__), setting.conf.get("system").get("project_name") + ".pid"), 'w') as pid:
            pid.write(str(os.getpid()))

    # check config
    ConfigParser(setting.conf).check()
    if ArgumentParser.args['test']:
        logger.info('Test successfully, ' + str(len(setting.conf.get('dns_servers', []))) + ' server(s) found.')
        exit(0)

    # signal
    from utils import system
    system.register_sighandler(DNSServerLoader.stop, 2, 3, 15)
    system.register_sighandler(DNSServerLoader.reload, 10)

    # start server threads
    DNSServerLoader.daemon()


def main():
    import errno
    try:
        start()
    except IOError as e:
        # skip Interrupted function call in Windows
        if e.errno != errno.EINTR:
            raise
    except SystemExit:
        pass
    except:
        import traceback
        traceback.print_exc()
        exit(-1)
    finally:
        # delete pid file
        try:
            if not ArgumentParser.args['test']:
                os.remove(os.path.join(os.path.dirname(__file__), PROJ + '.pid'))
        except:
            pass


if __name__ == "__main__":
    main()
