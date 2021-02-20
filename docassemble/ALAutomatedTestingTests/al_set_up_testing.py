import requests
import re
from nacl import encoding, public
import codecs
from base64 import b64encode
import json
from docassemble.base.util import log
from docassemble.base.core import DAObject
#from docassemble.base.util import DAFileList, DAFile

# reference:
# https://gist.github.com/JeffPaine/3145490
# https://docs.github.com/en/free-pro-team@latest/rest/reference/issues#create-an-issue
# https://github.com/SuffolkLITLab/docassemble-GithubFeedbackForm
# https://vaibhavsagar.com/blog/2020/05/04/github-secrets-api/
# https://github.com/berit/docassemble-initializecucumber/blob/main/docassemble/initializecucumber/test.py
# Create org secret: https://docs.github.com/en/rest/reference/actions#create-or-update-an-organization-secret
# Create repo secret: https://docs.github.com/en/rest/reference/actions#create-or-update-a-repository-secret


class TestInstaller(DAObject):
  def init( self, *pargs, **kwargs ):
    super().init(*pargs, **kwargs)
  
  def send_da_auth_secrets( self ):
    """Set GitHub repo secrets the tests need to log into the da server and
    create projects to run interviews to test."""
    self.put_secret( secret_name='PLAYGROUND_EMAIL', secret_value=self.email )
    self.put_secret( secret_name='PLAYGROUND_PASSWORD', secret_value=self.password )
    self.set_da_server_info()
    self.put_secret( secret_name='PLAYGROUND_ID', secret_value=self.playground_id )
    return self
  
  def put_secret( self, secret_name='', secret_value='' ):
    """Add one secret to the GitHub repo."""
    # Convert the message and key to Uint8Array's (Buffer implements that interface)
    encrypted_key = public.PublicKey( self.public_key.encode("utf-8"), encoding.Base64Encoder() )
    sealed_box = public.SealedBox( encrypted_key )
    # Encrypt using LibSodium.
    encrypted = sealed_box.encrypt( secret_value.encode( "utf-8" ))
    # Base64 the encrypted secret
    base64_encrypted = b64encode( encrypted ).decode( "utf-8" )
    #log( base64_encrypted, 'console' )
    
    secret_url = self.github_repo_base + "/actions/secrets/" + secret_name
    secret_payload = '{"encrypted_value":"' + base64_encrypted + '", "key_id":"' + self.key_id + '"}'
    secret_headers = {
      'Accept': "application/vnd.github.v3+json",
      'Authorization': self.basic_auth,
    }
    
    secret_response = requests.request( "PUT", secret_url, data=secret_payload, headers=secret_headers )
    #log( 'secret_response.text', 'console' )
    #log( secret_response.text, 'console' )
    
    # TODO: Check there was no error
    
    # Cannot get the value of the secret to see if we're setting it correctly
    # Can at least check that the secret exists
    response = requests.request( "GET", secret_url, data="", headers=secret_headers )
    log( response.text, 'console' )
    
    return self

  def set_github_auth( self ):
    """Set values needed for GitHub authorization.
    Needs self.user_name, self.repo_name, and self.token."""
    self.get_github_info_from_url()  # To implement
    
    # The value for the GitHub 'Authorization' key
    auth_bytes = codecs.encode(bytes( self.user_name + ':' + self.token, 'utf8'), 'base64')
    self.basic_auth = 'Basic ' + auth_bytes.decode().strip()
    
    # The base url string needed for making requests to the repo.
    self.github_repo_base = "https://api.github.com/repos/" + self.user_name + "/" + self.repo_name
    
    self.set_key_values()
    return self
  
  def get_github_info_from_url( self, repo_url='' ):
    """Use repo address to parse out user name and repo name."""
    return self
  
  def set_key_values( self ):
    """Gets and sets GitHub key id for the repo. Needed for auth to
    set secrets, etc. Needs set_github_auth()"""
    key_url = self.github_repo_base + "/actions/secrets/public-key"
    key_payload = ""
    key_headers = {
      'Accept': 'application/vnd.github.v3+json',
      'Authorization': self.basic_auth,
    }
    
    key_response = requests.request( 'GET', key_url, data=key_payload, headers=key_headers )
    key_json = json.loads( key_response.text )
    self.key_id = key_json[ 'key_id' ]
    self.public_key = key_json[ 'key' ]
    return self
    
  def set_da_server_info( self ):
    server_match = re.match( r"^(.+)\/interview\?i=docassemble\.playground", self.interview_url)
    if server_match is None:
      self.server_url = None
    else:
      self.server_url = server_match.group(1)
      
    id_match = re.match( r"^.+(?:interview\?i=docassemble\.playground)(\d+)(?:.*)$", self.interview_url )
    if id_match is None:
      self.playground_id = None
    else:
      self.playground_id = id_match.group(1)
    
    log( self.server_url, 'console' )
    log( self.playground_id, 'console' )
    #return { "server_url": self.server_url, "playground_id": self.playground_id }
    return self
#
#  def get_files( self ):
#    pass
#
#  def transform_files( self ):
#    pass
#
#  def push_to_new_branch( self ):
#    pass
#
#  def make_pull_request( self ):
#    pass
