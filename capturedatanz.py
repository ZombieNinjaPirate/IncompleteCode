#!/usr/bin/env python


"""Extract information from a Capture Data image."""


"""
Copyright (c) 2014, Are Hansen.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


__autor__ = 'Are Hansen'
__date__ = '2014, June 10'
__version_ = 'DEV 0.0.3'


import glob
import os
import re
import sys


def find_mounted():
	"""Find mounted ACCD images, append to list and return it if value is non-zero."""
	imgpath = '/Volumes'
	img_list = []

	for img in os.listdir(imgpath):
		if re.search('ACCD', img):
	 		img_list.append('{0}/{1}'.format(imgpath, img))

	if len(img_list) == 0:
		print '\nERROR: You have no mounted Capture Data images!\n'
		sys.exit(1)

	return img_list


def select_dmg(dmglist):
	"""List the mounted ACCD images, hold for user selection and return it after validation."""
	item_numb = 1

	print '\n'

	for dmg in dmglist:
		dmg = dmg.split('/')[2]
		print '{0} - {1}'.format(item_numb, dmg)
		item_numb = item_numb + 1

	print '\n'

	try:
		usr_select = int(raw_input('Choose Capture Data file: '))
	except ValueError:
		print '\nERROR: You must enter a number!\n'
		sys.exit(1)

	try:
		usr_select = usr_select - 1
		imgpath = dmglist[usr_select]
	except IndexError:
		print '\nERROR: IndexError in img_list!\n'
		sys.exit(1)

	return imgpath


def kernel_panics(dmgpath):
	"""Get panic log information. """
	logpath = '{0}/{1}'.format(dmgpath, 'DiagnosticReports')
	panic_logs = []
	panic_name = {}

	os.chdir(logpath)

	for logs in glob.glob('*.panic'):
		panic_logs.append(logs)

	for log in panic_logs:
		with open(log, 'r') as plog:
			log = log.split('_')

			print 'Time: {0}'.format(log[1])
			
			for kp in plog.readlines():
				if 'BSD process name corresponding to current' in kp:
					print '- BSD process:', kp.split(':')[-1].lstrip()


def main():
	"""Ze bozz function."""
	accdimg = find_mounted()
	accdpath = select_dmg(accdimg)
	kernel_panics(accdpath)


if __name__ == '__main__':
	main()
