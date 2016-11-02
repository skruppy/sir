Sir Tificate
============
`sir` will help you to do automated TLS certificate roll-over, including TLSA updates.
It does his job in two phases.
The second phase hast to be delayed by a few TTLs of the TLSA records.
Each phase consists of steps, which can be executed separately to use the appropriate system user with minimal access to keys and other systems.

```
usage: sir.py [-h] [-v] [-c CONFIG] STEP

I will help you to do automated TLS certificate roll-overs, including TLSA updates.
 - Sir Tificate
         ___________
        |           |
        |           |
        |           |
     ___,           .___
    /___________________\
         ___
        /   \
       |     |
        \___/
           ___ ___
    |`.__.`   V   `.__.`|
     \_______/ \_______/

positional arguments:
  STEP                  The step you would to take

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Increase debug level to INFO and with a second -v to
                        DEBUG
  -c CONFIG, --config CONFIG
                        config file

The steps:
 * phase2: Do the rollover and updatetlsa steps
 * rollover: Call your roll-over scripts to install the new certs
 * addtlsa: Add TLSA records for the new certs
 * full: Do all steps
 * updatetlsa: Delete all TLSA records an add only the new ones
 * phase1: Do the key, cert and addtlsa steps
 * key: Create private keys and associated csrs
 * cert: Call the sign script to create certs and chains
```

Installation
------------
First you should get the source
```bash
git clone https://github.com/Skrupellos/sir.git
```

Then you can create working and config directories (as root).
```bash
mkdir -p /etc/sir/{rollover,sign} /var/lib/sir/{keys,csrs,certs,chains}
useradd -r sirpriv
useradd -r sirpub
useradd -r sirns
chown -r sirpriv:sirpriv /var/lib/sir/{keys,csrs}
chown -r sirpub:sirpub   /var/lib/sir/{certs,chains}
chmod -r o-rwx /var/lib/sir/keys
```

Now you can create a config in `/etc/sir/conf.yaml` and add some sign and roll-over scripts in `/etc/sir/`.

There exists also a [Gentoo](https://www.gentoo.org/) [ebuild](https://github.com/lorem-ipsum/ebuilds/blob/master/net-misc/sir/sir-9999.ebuild).

Using cron
----------
[cron-phase1](https://github.com/Skrupellos/sir/blob/master/examples/cron-phase1)
```bash
## Script for Phase 1
set -e

sudo -u sirpriv sir.py key
sudo -u sirpub  sir.py cert
sudo -u sirns   sir.py addtlsa
```
[cron-phase2](https://github.com/Skrupellos/sir/blob/master/examples/cron-phase2)
```bash
## Script for Phase 2
set -e

## If you don't need the cert specific roll-over scripts and/or don't trust a
## Sir, you can also call your roll-over scripts directly and use globs.
sir.py rollover
sudo -u sirns sir.py updatetlsa
```
