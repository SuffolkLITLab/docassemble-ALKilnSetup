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

setup(name='docassemble.ALAutomatedTestingTests',
      version='0.3.1',
      description=('A docassemble extension for testing the AssemblyLine automated integrated testing framework.'),
      long_description='# docassemble.ALAutomatedTestingTests\r\n\r\nA docassemble extension for testing the AssemblyLine automated integrated testing framework.\r\n\r\n# Functionality contained in this repo\r\n\r\n## Help set up automated integrated testing\r\n\r\nIn an online form, a developer can give permissions and info that will set up testing for a docassemble package. It requires a GitHub token with repo and workflow permissions. It will add necessary GitHub secrets, make a new branch, push files to the `sources` directory, and make a PR with that branch.\r\n\r\n### TODO\r\n1. Install interview on server and add link here.\r\n1. Improve error messages.\r\n1. Clarify instructions.\r\n\r\n## Test the testing framework\r\n\r\nProvide an interview with combinations of fields that will allow the testing framework to test its own functionality.\r\n\r\n### TODO\r\n1. See issues\r\n\r\n## TODO\r\n1. Add test generator to this repo.\r\n',
      long_description_content_type='text/markdown',
      author='',
      author_email='example@example.com',
      license='The MIT License (MIT)',
      url='https://docassemble.org',
      packages=find_packages(),
      namespace_packages=['docassemble'],
      install_requires=['PyGithub>=1.55', 'PyNaCl>=1.4.0', 'requests>=2.25.1'],
      zip_safe=False,
      package_data=find_package_data(where='docassemble/ALAutomatedTestingTests/', package='docassemble.ALAutomatedTestingTests'),
     )

