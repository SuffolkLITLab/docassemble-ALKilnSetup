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
  
  def set_da_info( self ):
    """Use the interview url to get the user's Playground id."""
    # Can we get granular with error messages?
    log( 1, 'console' )
    server_match = re.match( r"^(http.+)\/interview\?i=docassemble\.playground(\d+).*$", self.playground_url )
    if server_match is None:
      log( 2, 'console' )
      self.server_url = None
      self.playground_id = None
      # TODO: Show error
    else:
      log( 3, 'console' )
      # TODO: More fine-grained validation of this information
      self.server_url = server_match.group(1)
      self.playground_id = server_match.group(2)
    
    # TODO: Is it possible to try to log into their server to
    # make sure they've given the correct information?
    log( 4, 'console' )
    return self
  
  # da auth and pushing
  def set_github_info( self ):
    return self
  
  def update_github( self ):
    return self
  
  # handle errors
    