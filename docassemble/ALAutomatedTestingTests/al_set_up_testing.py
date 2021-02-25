from github import Github  # PyGithub
import requests
from nacl import encoding, public  # pynacl
# TODO: Reduce to just one encryption library :/
import codecs
from base64 import b64encode
import re
import json
from docassemble.base.util import log
from docassemble.base.core import DAObject

# reference:
# Mostly: https://pygithub.readthedocs.io/en/latest/introduction.html

class TestInstaller(DAObject):
  def init( self, *pargs, **kwargs ):
    super().init(*pargs, **kwargs)
  
  # da info
  def set_da_info( self ):
    return self
  
  # da auth and pushing
  def set_github_info( self ):
    return self
  
  def update_github( self ):
    return self
  
  # handle errors
    