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

import copy
import logging
import pprint
import yaml
import sir.util


class Context:
	@property
	def position(self):
		return '.'.join(self.__location)
	
	
	def __init__(self):
		self.__location = ['Root']
		
		## Parsed and validated (actual config)
		self.root   = {}
		self.cert   = {}
		self.domain = {}
		self.zone   = {}
		self.record = {}
		
		## Just fallback yaml
		self.fallback = {
			'defaultCerts'   : [],
			'defaultDomains' : [],
			'defaultZones'   : [],
			'defaultRecords' : [],
		}
	
	
	def enter(self, type):
		new = copy.deepcopy(self)
		new.__location.append(type)
		return new
	
	
	def updateFallback(self, key, y):
		if key in y:
			if y[key] is None:
				self.fallback[key] = []
			elif isinstance(y[key], list):
				self.fallback[key] = y[key]
			else:
				raise Exception('%s @ %s is not a (empty) List' % (key, self.position))
	
	
	## ...Defauts() can't have child ...Defaults(), since it would be redundant
	## to sibbling ...Defaults(), which are nice to read. A redundant child and
	## sibbling definition would result in confliting definitions.
	## 
	## Same for default...(). This would allow a strange overwriting behaviour.
	## It would also lead to the pollution of the template object's parameter
	## namespace, which is later passed directly to the object constructor.
	def updateCert(self, y):
		for key in ['name', 'signScript', 'rolloverScript', 'type', 'extraConf', 'keyDir', 'csrDir', 'certDir', 'chainDir']:
			if key in y:
				self.cert[key] = y[key]
	
	
	def updateDomain(self, y):
		for key in ['name']:
			if key in y:
				self.domain[key] = y[key]
	
	
	def updateZone(self, y):
		for key in ['name', 'server', 'port', 'keyFile']:
			if key in y:
				self.zone[key] = y[key]
	
	
	def updateRecord(self, y):
		for key in ['port', 'ttl']:
			if key in y:
				self.record[key] = y[key]
		
		if 'usage' in y:
			self.record['usage'] = sir.model.TlsaUsage[y['usage']]
		
		if 'selector' in y:
			self.record['selector'] = sir.model.TlsaSelector[y['selector']]
		
		if 'type' in y:
			self.record['type'] = sir.model.TlsaType[y['type']]



class ConfigParser:
	@property
	def rolloverScript(self):
		return self.__rolloverScript
	
	
	@property
	def signScript(self):
		return self.__signScript
	
	
	
	def __init__(self, fileName, certs, domains, zones):
		self.__certs   = certs
		self.__domains = domains
		self.__zones   = zones
		
		self.__rolloverScript = None
		
		self.__parseRoot(Context(), yaml.load(sir.util.readFile(fileName)))
	
	
	
	
	def __parseRoot(self, c, y):
		## Update current element
		pass
		
		## Update descendant templates
		for key, fn in [
			('certDefaults'   , c.updateCert),
			('domainDefaults' , c.updateDomain),
			('zoneDefaults'   , c.updateZone),
			('recordDefaults' , c.updateRecord),
		]:
			if key in y:
				fn(y[key])
		
		## Collect fallbacks
		for key in [
			'defaultDomains',
			'defaultZones',
			'defaultRecords',
		]:
			c.updateFallback(key, y)
		
		## Do domething
		pass
		
		## Visit children
		for cert in (y['certs'] if 'certs' in y else c.fallback['defaultCerts']):
			self.__parseCert(c.enter('Cert'), cert)
	
	
	def __parseCert(self, c, y):
		## Update current element
		c.updateCert(y)
		
		## Update descendant templates
		for key, fn in [
			('domainDefaults' , c.updateDomain),
			('zoneDefaults'   , c.updateZone),
			('recordDefaults' , c.updateRecord),
		]:
			if key in y:
				fn(y[key])
		
		## Collect fallbacks
		for key in [
			'defaultZones',
			'defaultRecords',
		]:
			c.updateFallback(key, y)
		
		## Do domething
		self.__certs.add(**c.cert)
		
		## Visit children
		for domain in (y['domains'] if 'domains' in y else c.fallback['defaultDomains']):
			self.__parseDomain(c.enter('Domain'), domain)
	
	
	
	def __parseDomain(self, c, y):
		## Update current element
		c.updateDomain(y)
		
		## Update descendant templates
		for key, fn in [
			('zoneDefaults'   , c.updateZone),
			('recordDefaults' , c.updateRecord),
		]:
			if key in y:
				fn(y[key])
		
		## Collect fallbacks
		for key in [
			'defaultRecords',
		]:
			c.updateFallback(key, y)
		
		## Do domething
		self.__certs.get(c.cert['name']).addDomain(self.__domains.get(c.domain['name']))
		
		## Visit children
		for zone in (y['zones'] if 'zones' in y else c.fallback['defaultZones']):
			self.__parseZone(c.enter('Zone'), zone)
	
	
	
	def __parseZone(self, c, y):
		## Update current element
		c.updateZone(y)
		
		## Update descendant templates
		for key, fn in [
			('recordDefaults' , c.updateRecord),
		]:
			if key in y:
				fn(y[key])
		
		## Collect fallbacks
		pass
		
		## Do domething
		pass
		
		## Visit children
		for record in (y['records'] if 'records' in y else c.fallback['defaultRecords']):
			self.__parseRecord(c.enter('Record'), record)
	
	
	
	def __parseRecord(self, c, y):
		## Update current element
		c.updateRecord(y)
		
		## Update descendant templates
		pass
		
		## Collect fallbacks
		pass
		
		## Do domething
		logging.debug('New record from config:\ncert: %s\ndomain: %s\nzone: %s\n record: %s', pprint.pprint(c.cert), pprint.pprint(c.domain), pprint.pprint(c.zone), pprint.pprint(c.record))
		
		zone = self.__zones.get(**c.zone)
		zoneDomain = zone.getZoneDomainOfDomain(self.__domains.get(c.domain['name']))
		port = zoneDomain.getPort(c.record['port'])
		c.record.pop('port', None)
		port.createRecord(self.__certs.get(c.cert['name']), **c.record)
		
		## Visit children
		pass
