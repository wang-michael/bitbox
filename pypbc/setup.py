#! /usr/bin/env python3
# python3 setup.py install
# pip3 install pypbc

from distutils.core import setup, Extension

pbc = Extension(	"pypbc",
				libraries=["pbc"],
				sources=["pypbc.c"]
			)

setup(	name="pypbc",
		version="0.0",
		description="a simple set of bindings to PBC's interface.",
		author="Geremy Condra",
		author_email="debatem1@gmail.com",
		url="geremycondra.net",
		py_modules=["test", "KSW"],
		ext_modules=[pbc]
)
