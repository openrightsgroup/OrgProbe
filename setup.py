#!/usr/bin/env python

from distutils.core import setup

import orgprobe

setup(name='OrgProbe',
      version=orgprobe.__version__,
      description='Blocked.org.uk probe software',
      author='Open Rights Group',
      author_email='blocked@openrightsgroup.org',
      url='https://github.com/openrightsgroup/OrgProbe',
      packages=['orgprobe'],
      scripts=['orgprobe-daemon'],
      requires=[
          'pika(>=1.2.0)',
          'requests(==2.25.0)',
          'configparser(==3.5.0)'
      ])
