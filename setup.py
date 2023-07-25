import os
import sys
from setuptools import setup, find_packages
from fnmatch import fnmatchcase
from distutils.util import convert_path

standard_exclude = ('*.pyc', '*~', '.*', '*.bak', '*.swp*')
standard_exclude_directories = ('.*', 'CVS', '_darcs', './build', './dist', 'EGG-INFO', '*.egg-info')

def find_package_data(where='.', package='', exclude=standard_exclude, exclude_directories=standard_exclude_directories):
    out = {}
    stack = [(convert_path(where), '', package)]
    while stack:
        where, prefix, package = stack.pop(0)
        for name in os.listdir(where):
            fn = os.path.join(where, name)
            if os.path.isdir(fn):
                bad_name = False
                for pattern in exclude_directories:
                    if (fnmatchcase(name, pattern)
                        or fn.lower() == pattern.lower()):
                        bad_name = True
                        break
                if bad_name:
                    continue
                if os.path.isfile(os.path.join(fn, '__init__.py')):
                    if not package:
                        new_package = name
                    else:
                        new_package = package + '.' + name
                        stack.append((fn, '', new_package))
                else:
                    stack.append((fn, prefix + name + '/', package))
            else:
                bad_name = False
                for pattern in exclude:
                    if (fnmatchcase(name, pattern)
                        or fn.lower() == pattern.lower()):
                        bad_name = True
                        break
                if bad_name:
                    continue
                out.setdefault(package, []).append(prefix+name)
    return out

setup(name='docassemble.ALKilnSetup',
      version='1.0.1',
      description=('A docassemble extension for testing the AssemblyLine automated integrated testing framework.'),
      long_description='# ALKiln support package\r\n\r\nAssembly Line Kiln (ALKiln) is a framework for automatically testing **any** [docassemble](https://docassemble.org/) package using GitHub. ALKiln is being developed as part of the SuffolkLITLab Document Assembly Line project. See [documentation for kiln](https://suffolklitlab.github.io/docassemble-AssemblyLine-documentation/docs/automated_integrated_testing).\r\n\r\nThis package supports ALKiln in different ways.\r\n\r\n## Tool to set up testing\r\n\r\n[Tap here to set up automated integrated testing for your docassemble interview](https://apps-dev.suffolklitlab.org/start/test-setup/).\r\n\r\nThis repo contains a step-by-step form that a developer can use to set up automated integrated testing for **any** docassemble package. It requires, among other things, a docassemble account and a temporary GitHub personal access token with correct permissions. It will add necessary GitHub secrets, make a new branch, push necessary files to that branch, and make a PR with that branch.\r\n\r\n## Test ALKiln itself\r\n\r\nThis package provides files that the ALKiln testing framework can use to test its own functionality. That includes tests for setting different types of fields, for observing the state of the page, and for getting error messages.\r\n',
      long_description_content_type='text/markdown',
      author='',
      author_email='example@example.com',
      license='The MIT License (MIT)',
      url='https://docassemble.org',
      packages=find_packages(),
      namespace_packages=['docassemble'],
      install_requires=['PyGithub>=1.59.0', 'PyNaCl>=1.5.0', 'docassemble.ALToolbox>=0.8.2', 'requests>=2.31.0'],
      zip_safe=False,
      package_data=find_package_data(where='docassemble/ALKilnSetup/', package='docassemble.ALKilnSetup'),
     )

