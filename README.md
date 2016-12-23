# dns-router

- Author: major1201
- Current version: 0.2

## Summary

A simple DNS server(with cache support) which can shunt your DNS requests towards different DNS servers.

## Get start

`-h` to see a help document
```
$ python dns-router.py -h
```

`-c` to specify a config file
```
$ python dns-router.py -c xxx.yml
```

`-t` to test a config file
```
$ python dns-router.py -t
```

to run dns-router
```
$ python dns-router.py
```

## Configuration

`dns-router.yml` is an example configuration

## Requirements

- dnslib `pip install dnslib`
- pyyaml `pip install pyyaml`
- six `pip install six`
- future `pip install future`
- python-memcached `pip install python-memcached`

## License

This project follows GNU General Public License v3.0.
