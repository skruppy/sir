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

import itertools
import logging
import shlex
import subprocess
import os
import contextlib



def readFile(filename):
	with open(filename) as f:
		return f.read()



def rmFile(filename):
	with contextlib.suppress(FileNotFoundError):
		os.remove(filename)



def sh(args, stdin = None):
	logging.info('Executing %s' % ' '.join(map(shlex.quote, args)))
	try:
		logging.debug('stdin:\n%s', stdin)
		stdout = subprocess.check_output(args, input = stdin, stderr = subprocess.STDOUT).decode("UTF-8")[:-1]
		logging.debug('stdout:\n%s', stdout)
		return stdout
	except subprocess.CalledProcessError as e:
		logging.error('Failed executing %s, the output was:\n-----------\n%s\n-----------', ' '.join(map(shlex.quote, args)), e.output.decode("UTF-8"))
		raise e



def noNone(v, replacement = ''):
	if v is None:
		return replacement
	else:
		return v



def groupBy(l, f):
	return itertools.groupby(sorted(l, key=f), f)



## http://stackoverflow.com/a/13624858
class classproperty(object):
	def __init__(self, fget):
		self.fget = fget
	
	def __get__(self, owner_self, owner_cls):
		return self.fget()
	
	def __call__(self):
		return self.fget()
