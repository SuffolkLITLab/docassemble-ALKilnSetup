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
  def set_github_auth( self ):
    """Get and set all the information needed to authorize to GitHub"""
    self.get_github_info_from_repo_url()
    
    # TODO: detect types of errors
    # Token doesn't work: github.GithubException.BadCredentialsException (401, 403)
    # Repo doesn't exist: github.GithubException.UnknownObjectException (404)
    
    self.github = Github( self.token )
    # self.github.enable_console_debug_logging()
    log( 1, 'console' )
    log( self.github.FIX_REPO_GET_GIT_REF, 'console' )  # True
    log( 2, 'console' )
    #log( self.github.per_page, 'console' )
    #log( 3, 'console' )
    #log( self.github.rate_limiting, 'console' )
    log( 4, 'console' )
    log( self.github.oauth_scopes, 'console' )  # None
    log(5, 'console' )
    user = self.github.get_user()
    log(6, 'console' )
    self.repo = user.get_repo( self.repo_name )
    log( 'a', 'console' )
    self.owner_name = self.repo.owner.login
    log( 'b', 'console' )
    self.user_name = self.github.get_user().login  # feedback for the user
    log( 'c', 'console' )
    # TODO: Check user permissions: https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.get_collaborator_permission
    #self.repo.get_collaborator_permission( self.user_name )
    
    return self
  
  def set_auth_for_secrets( self ):
    """Separated to allow easier removal when library finally supports secrets"""
    
    return self
  
  def get_github_info_from_repo_url( self ):
    """Use repo address to parse out owner name and repo name. Needs self.repo_url"""
    # Match either the actual URL or the clone HTTP or SSH URL
    matches = re.match(r"^.+github.com(?:\/|:)([^\/]*)\/([^\/.]*)(?:\..{3})?", self.repo_url)
    if matches:
      self.repo_name = matches.group(2)
    else:
      self.repo_name = None
      
    return self
  
  def update_github( self ):
    return self
  
  # handle errors
    