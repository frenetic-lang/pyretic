#!/usr/bin/env python

# This file is currently pretty bare. Perhaps you would like to fix it up.

from distutils.core import setup, Command

class PyTest(Command):
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys,subprocess
        errno = subprocess.call([sys.executable, 'runtests.py'])
        raise SystemExit(errno)

setup(name='Frenetic',
      version='1.2',   # do we have an official version number?
      url="http://www.frenetic-lang.org/",
      license="BSD",
      py_modules=['frenetic'],
      cmdclass = {"test": PyTest},
      )
