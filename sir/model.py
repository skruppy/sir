# Sir helps you to do automated TLS certificate rollovers, including TLSA updates.
# Copyright (C) 2015  Skruppy <skruppy@onmars.eu>
# 
# This file is part of Sir.
# 
# Sir is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Sir is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Sir.  If not, see <http://www.gnu.org/licenses/>.

from OpenSSL import crypto
from OpenSSL._util import lib as cryptolib
import binascii
import enum
import hashlib
import logging
import operator
import os
import shlex
import sys
import sir.util



class TlsaUsage(enum.Enum):
	PKIX_TA = 0 ## Server cert must be signed by a CA known to the client and the given cert must be somewhere in the cain.
	PKIX_EE = 1 ## Server cert must be signed by a CA known to the client and the given cert must be the server cert.
	DANE_TA = 2 ## The given cert must be somewhere in the cain.
	DANE_EE = 3 ## The given cert must be the server cert.



class TlsaSelector(enum.Enum):
	FULL = 0 ## Every aspect of the cert.
	SPKI = 1 ## Just the public key.



class TlsaType(enum.Enum):
	EXACT  = 0 ## The full data.
	SHA256 = 1 ## SHA-256 of the data.
	SHA512 = 2 ## SHA-512 of the data.



class Domain:
	@property
	def name(self):
		return self.__name
	
	
	@property
	def san(self):
		return 'DNS:%s' % self.__name
	
	
	def __init__(self, name):
		self.__name  = name
	
	
	def __str__(self):
		return 'Domain %s' % self.__name



class DomainSet:
	__domains = {}
	
	
	def get(self, name):
		if not name in self.__domains:
			self.__domains[name] = Domain(name)
		
		return self.__domains[name]
	
	
	def foo(self):
		return self.__domains.values()



class Cert:
	@sir.util.classproperty
	def NO_SCRIPT():
		return 'none'
	
	
	@sir.util.classproperty
	def DEFAULT_TYPE():
		return 'rsa:4096'
	
	
	@sir.util.classproperty
	def DEFAULT_EXTRA_CONF():
		return ''
	
	
	@sir.util.classproperty
	def DEFAULT_KEY_DIR():
		return '/var/lib/sir/keys/'
	
	
	@sir.util.classproperty
	def DEFAULT_CSR_DIR():
		return '/var/lib/sir/csrs/'
	
	
	@sir.util.classproperty
	def DEFAULT_CERT_DIR():
		return '/var/lib/sir/certs/'
	
	
	@sir.util.classproperty
	def DEFAULT_CHAIN_DIR():
		return '/var/lib/sir/chains/'
	
	
	@property
	def name(self):
		return self.__name
	
	
	@property
	def fileName(self):
		return '%s.pem' % self.__name
	
	
	@property
	def domains(self):
		return self.__domains.copy()
	
	
	@property
	def keyFile(self):
		return os.path.join(self.__keyDir, self.fileName)
	
	
	@property
	def csrFile(self):
		return os.path.join(self.__csrDir, self.fileName)
	
	
	@property
	def certFile(self):
		return os.path.join(self.__certDir, self.fileName)
	
	
	@property
	def chainFile(self):
		return os.path.join(self.__chainDir, self.fileName)
	
	
	def __init__(self,
			name, signScript = None, rolloverScript = None,
			type    = DEFAULT_TYPE()     , extraConf = DEFAULT_EXTRA_CONF(),
			
			## The following default values are redundant in every cert (they
			## should actually be the same), but this prevents creating
			## incomplete objects. (Strange problem with the chicken and the egg
			## during app startup and configuration.)
			keyDir  = DEFAULT_KEY_DIR()  , csrDir    = DEFAULT_CSR_DIR(),
			certDir = DEFAULT_CERT_DIR() , chainDir  = DEFAULT_CHAIN_DIR(),
	):
		self.__name           = name
		
		self.__signScript     = signScript
		self.__rolloverScript = rolloverScript
		self.__type           = type
		self.__extraConf      = extraConf
		self.__keyDir         = keyDir
		self.__csrDir         = csrDir
		self.__certDir        = certDir
		self.__chainDir       = chainDir
		
		self.__domains        = []
		self.__hashCache      = {}
	
	
	def __str__(self):
		return 'Cert %s' % self.name
	
	
	def addDomain(self, domain):
		if not domain in self.__domains:
			self.__domains.append(domain)
		## TODO Raise exception, if domain already exists?
	
	
	def createKeyAndCsr(self):
		if not self.__domains:
			return
		
		sir.util.rmFile(self.keyFile)
		sir.util.rmFile(self.csrFile)
		
		args = [
			'openssl', 'req',
			'-batch',               ## Don't ask anything
			'-new',                 ## ??
			'-nodes',               ## Don't encrypt key (TODO needed for batch?)
			'-newkey', self.__type,
			'-keyout', self.keyFile,
			'-out',    self.csrFile
		]
		
		if(len(self.__domains) > 1):
			args.extend([
				'-reqexts', 'SAN',
				'-config', '/proc/self/fd/0'
			])
			
			subject = '/'
			stdin = ('%s\n[SAN]\nsubjectAltName=%s\n%s\n' % (
				sir.util.readFile('/etc/ssl/openssl.cnf'),
				','.join(map(operator.attrgetter('san'), self.__domains)),
				self.__extraConf,
			)).encode('UTF-8')
		
		else:
			subject = '/CN=%s' % self.__domains[0].name
			stdin = None
		
		args.extend(['-subj', subject])
		sir.util.sh(args, stdin)
	
	
	def __actualScript(self, type, userPath):
		if userPath is None:
			## Try specific fallback script
			script = '/etc/sir/%s/%s' % (type, self.__name)
			if os.path.isfile(script) and os.access(script, os.X_OK):
				logging.info('No %sScript for %s specified, but %s found', type, self.__name, script)
				return script
			
			## Try specific global script
			script = os.path.join('/etc/sir/%s' % type)
			if os.path.isfile(script) and os.access(script, os.X_OK):
				logging.info('No %sScript for %s specified, but %s found', type, self.__name, script)
				return script
			
			## No script found
			logging.info('No %sScript found for %s', type, self.__name)
			return None
		
		else:
			## No script should be used
			if userPath == NO_SCRIPT:
				return None
			
			## Use user script
			logging.info('Using %sScript \'%s\' for %s', type, userPath, self.__name)
			return userPath
	
	
	def createCertAndChain(self):
		if not self.__domains:
			return
		
		script = self.__actualScript('sign', self.__signScript)
		if script is not None:
			print(sir.util.sh(shlex.split(script) + [self.csrFile, self.certFile, self.chainFile]))
	
	
	def rollover(self):
		if not self.__domains:
			return
		
		script = self.__actualScript('rollover', self.__rolloverScript)
		if script is not None:
			print(sir.util.sh(shlex.split(script) + [self.keyFile, self.certFile, self.chainFile]))
	
	
	def getHash(self, selector, type):
		key = (selector, type)
		if key not in self.__hashCache:
			cert = crypto.load_certificate(crypto.FILETYPE_PEM, sir.util.readFile(self.certFile))
			
			if selector == TlsaSelector.FULL:
				data = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
			
			elif selector == TlsaSelector.SPKI:
				bio = crypto._new_mem_buf()
				cryptolib.i2d_PUBKEY_bio(bio, cert.get_pubkey()._pkey)
				data = crypto._bio_to_string(bio)
			
			else:
				raise Exception('Unknown TLSA selector %s' % selector)
			
			
			if type == TlsaType.EXACT:
				self.__hashCache[key] = binascii.b2a_hex(data).decode('ascii')
			
			elif type == TlsaType.SHA256:
				self.__hashCache[key] = hashlib.sha256(data).hexdigest()
			
			elif type == TlsaType.SHA512:
				self.__hashCache[key] = hashlib.sha512(data).hexdigest()
			
			else:
				raise Exception('Unknown TLSA type %s' % type)
		
		return self.__hashCache[key]



class CertSet:
	__certs = {}
	
	
	def add(self, name, *args, **kwargs):
		if name in self.__certs:
			raise Exception('Cert %s already created' % name)
		
		self.__certs[name] = Cert(name, *args, **kwargs)
	
	
	def get(self, cert):
		return self.__certs[cert]
	
	
	def foo(self):
		return self.__certs.values()



class Record:
	@sir.util.classproperty
	def DEFAULT_TTL():
		return 3600
	
	@sir.util.classproperty
	def DEFAULT_USAGE():
		return TlsaUsage.DANE_EE
	
	@sir.util.classproperty
	def DEFAULT_SELECTOR():
		return TlsaSelector.SPKI
	
	@sir.util.classproperty
	def DEFAULT_TYPE():
		return TlsaType.SHA256
	
	@property
	def port(self):
		return self.__port
	
	@property
	def cert(self):
		return self.__cert
	
	@property
	def ttl(self):
		return self.__ttl
	
	@property
	def usage(self):
		return self.__usage
	
	@property
	def selector(self):
		return self.__selector
	
	@property
	def type(self):
		return self.__type
	
	@property
	def rdata(self):
		return self.__rdata
	
	@property
	def name(self):
		if self.__port.port == ZoneDomain.WILDCARD:
			port = '*'
		else:
			port = '_%s' % port
		
		return '%s._tcp.%s' % (
			port,
			self.__port.zoneDomain.domain.name,
		)
	
	@property
	def record(self):
		return '%s %s TLSA %s %s %s %s' % (
			self.name,
			self.__ttl,
			self.__usage.value,
			self.__selector.value,
			self.__type.value,
			self.__cert.getHash(self.__selector, self.__type)
		)
	
	@property
	def add(self):
		return 'update add %s' % (self.record)
	
	@property
	def delete(self):
		return 'update delete %s' % (self.record)
	
	@property
	def deleteAll(self):
		return 'update delete %s TLSA' % (self.name)
	
	def __init__(self, port, cert, ttl = DEFAULT_TTL(), usage = DEFAULT_USAGE(), selector = DEFAULT_SELECTOR(), type = DEFAULT_TYPE()):
		self.__port     = port
		self.__cert     = cert
		self.__ttl      = ttl
		self.__usage    = usage
		self.__selector = selector
		self.__type     = type



class Port:
	@property
	def zoneDomain(self):
		return self.__zoneDomain
	
	@property
	def port(self):
		return self.__port
	
	@property
	def records(self):
		return self.__records.values()
	
	def __init__(self, zoneDomain, port):
		self.__zoneDomain = zoneDomain
		self.__port = port
		self.__records = {}
	
	## Here we break with get...() and autocreation of sub-items.
	def createRecord(self, cert, *args, **kwargs):
		if cert in self.__records:
			raise Exception('%s has already a record for %s' % (str(self), cert.name))
		
		if self.__zoneDomain.domain not in cert.domains:
			raise Exception('You can\'t add %s to %s, hence it\'s domain (%s) is not in the cert' % (str(cert), str(self), self.__zoneDomain.domain))
		
		record = Record(self, cert, *args, **kwargs)
		self.__records[cert] = record
		return record



class ZoneDomain:
	@sir.util.classproperty
	def WILDCARD():
		return 'wildcard'
	
	@property
	def zone(self):
		return self.__zone
	
	@property
	def domain(self):
		return self.__domain
	
	@property
	def hasWildcardPorts(self):
		return ZoneDomain.WILDCARD in self.__ports
	
	@property
	def hasNumericPorts(self):
		return self.__ports and ZoneDomain.WILDCARD not in self.__ports
	
	@property
	def ports(self):
		return self.__ports.values()
	
	def __init__(self, zone, domain):
		self.__zone   = zone
		self.__domain = domain
		self.__ports  = {}
	
	def getPort(self, port):
		if self.hasWildcardPorts and (port != ZoneDomain.WILDCARD):
			raise Exception('%s is a wildcard port domain, therefore you can\'t add port %s' % (str(self), port))
		
		elif self.hasNumericPorts and (port == ZoneDomain.WILDCARD):
			raise Exception('%s is a numeric port domain, therefore you can\'t add a wildcard' % str(self))
		
		if port not in self.__ports:
			self.__ports[port] = Port(self, port)
		
		return self.__ports[port]



class Zone:
	@sir.util.classproperty
	def DEFAULT_KEY_FILE():
		return None
	
	@sir.util.classproperty
	def DEFAULT_SERVER():
		return 'localhost'
	
	@sir.util.classproperty
	def DEFAULT_PORT():
		return 53
	
	@property
	def zone(self):
		return self.__zone
	
	@property
	def keyFile(self):
		return self.__keyFile
	
	@property
	def server(self):
		return self.__server
	
	@property
	def port(self):
		return self.__port
	
	@property
	def connection(self):
		return (self.__server, self.__port)
	
	@property
	def zoneDomains(self):
		return self.__zoneDomains.values()
	
	def __init__(self, name, keyFile = DEFAULT_KEY_FILE(), server = DEFAULT_SERVER(), port = DEFAULT_PORT()):
		self.__zone        = name
		self.__keyFile     = keyFile
		self.__server      = server
		self.__port        = port
		self.__zoneDomains = {}
	
	def getZoneDomainOfDomain(self, domain):
		if not domain.name in self.__zoneDomains:
			if not domain.name.endswith(self.__zone):
				raise Exception('Domain %s is not part of %s, therfore your can\'t add it.' % (str(self), domain.name))
			
			self.__zoneDomains[domain.name] = ZoneDomain(self, domain)
		
		return self.__zoneDomains[domain.name]



class ZoneSet:
	__zones = {}
	
	
	def get(self, name, keyFile = Zone.DEFAULT_KEY_FILE, server = Zone.DEFAULT_SERVER, port = Zone.DEFAULT_PORT):
		key = (name, keyFile, server, port)
		
		if not key in self.__zones:
			self.__zones[key] = Zone(*key)
		
		return self.__zones[key]
	
	
	def keys(self):
		return self.__zones.values()