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

import argparse
import logging
import operator
import shlex
import sir.config
import sir.model
import sir.util



class Sir:
	def __init__(self):
		self.__certs   = sir.model.CertSet()
		self.__domains = sir.model.DomainSet()
		self.__zones   = sir.model.ZoneSet()
		
		self.__steps = {
			'key': {
				'fn'  : self.__stepCreateKeyAndCsr,
				'dsc' : 'Create private keys and associated csrs',
			},
			'cert': {
				'fn'  : self.__stepCreateCertAndChain,
				'dsc' : 'Call the sign script to create certs and chains',
			},
			'addtlsa': {
				'fn'  : self.__stepAddTlsa,
				'dsc' : 'Add TLSA records for the new certs',
			},
			'rollover': {
				'fn'  : self.__stepRollover,
				'dsc' : 'Call your roll-over scripts to install the new certs',
			},
			'updatetlsa': {
				'fn'  : self.__stepUpdateTlsa,
				'dsc' : 'Delete all TLSA records an add only the new ones',
			},
			'phase1': {
				'fn'  : self.__stepPhase1,
				'dsc' : 'Do the key, cert and addtlsa steps',
			},
			'phase2': {
				'fn'  : self.__stepPhase2,
				'dsc' : 'Do the rollover and updatetlsa steps',
			},
			'full': {
				'fn'  : self.__stepFull,
				'dsc' : 'Do all steps',
			},
		}
		
		
	
	
	def __nsupdate(self, onRecord = None, onName = None):
		## Iterate over key files
		for keyFile, keyFileZones in sir.util.groupBy(self.__zones.keys(), lambda z: sir.util.noNone(z.keyFile)):
			script = ''
			
			## Iterate over server using a keyfile
			for connection, serverZones in sir.util.groupBy(keyFileZones, lambda z: z.connection):
				script += 'server %s %s\n' % connection
				
				## Iterate over zones on a server
				for zone in serverZones:
					script += 'zone %s.\n' % zone.zone
					
					## Iterate over names in a zone
					for domain in zone.zoneDomains:
						if not onName is None:
							script += '%s\n' % onName(list(list(domain.ports)[0].records)[0])
						
						## Iterate over records (of different certs) for a name
						for port in domain.ports:
							for record in port.records:
								if not onRecord is None:
									script += '%s\n' % onRecord(record)
					
					script += 'send\n'
			
			args = ['nsupdate']
			if keyFile != '':
				args.extend(['-k', keyFile])
			
			print(sir.util.sh(args, script.encode('UTF-8')))
	
	
	## Step 1.1 (create certs)
	def __stepCreateKeyAndCsr(self):
		for cert in self.__certs.foo():
			cert.createKeyAndCsr()
	
	
	## Step 1.2 (sign certs)
	def __stepCreateCertAndChain(self):
		for cert in self.__certs.foo():
			cert.createCertAndChain()
	
	
	## Step 1.3 (*Add* new TLSA records)
	def __stepAddTlsa(self):
		self.__nsupdate(operator.attrgetter('add'))
	
	
	## Step 2.1 (Rollover)
	def __stepRollover(self):
		for cert in self.__certs.foo():
			cert.rollover()
	
	
	## Step 2.2 (*Remove* old TLSA records)
	def __stepUpdateTlsa(self):
		self.__nsupdate(operator.attrgetter('add'), operator.attrgetter('deleteAll'))
	
	
	def __stepPhase1(self):
		self.__stepCreateKeyAndCsr()
		self.__stepCreateCertAndChain()
		self.__stepAddTlsa()
	
	
	def __stepPhase2(self):
		self.__stepRollover()
		self.__stepUpdateTlsa()
	
	
	def __stepFull(self):
		self.__stepPhase1()
		self.__stepPhase2()
	
	
	def main(self):
		logging.basicConfig(level=logging.DEBUG)
		
		stepDsc = ''
		for key, i in self.__steps.items():
			stepDsc += ' * %s: %s\n' % (key, i['dsc'])
		
		parser = argparse.ArgumentParser(
			formatter_class=argparse.RawDescriptionHelpFormatter,
			description='''
I will help you to do automated TLS certificate roll-overs, including TLSA updates.
 - Sir Tificate
         ___________
        |           |
        |           |
        |           |
     ___,           .___
    /___________________\\
         ___
        /   \\
       |     |
        \\___/
           ___ ___
    |`.__.`   V   `.__.`|
     \\_______/ \\_______/
''',
			epilog='''
The steps:
%s
''' % stepDsc,
		)
		
		parser.add_argument(
			'-v', '--verbose',
			help    = 'Increase debug level to INFO and with a second -v to DEBUG',
			action  = 'count',
			default = 0,
		)
		
		parser.add_argument(
			'-c', '--config',
			help    = 'config file',
			default = '/etc/sir/conf.yaml',
		)
		
		parser.add_argument(
			'step',
			metavar = 'STEP',
			choices = self.__steps,
			help    = 'The step you would to take',
		)
		
		args = parser.parse_args()
		
		
		## Setup logging
		if args.verbose == 0:
			logging.root.level = logging.WARN
		elif args.verbose == 1:
			logging.root.level = logging.INFO
		elif args.verbose >= 2:
			logging.root.level = logging.DEBUG
		
		## Read config
		sir.config.ConfigParser(args.config, self.__certs, self.__domains, self.__zones)
		
		## Do step
		self.__steps[args.step]['fn']()
