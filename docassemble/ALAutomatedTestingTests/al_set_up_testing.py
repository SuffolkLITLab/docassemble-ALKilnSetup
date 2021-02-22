import requests
import re
from nacl import encoding, public
import codecs
from base64 import b64encode
import json
from docassemble.base.util import log, zip_file
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
    self.set_github_auth()
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
    #log( 'base64_encrypted', 'console' )
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
  
  def get_github_info_from_url( self ):
    """Use repo address to parse out user name and repo name. Needs self.repo_url"""
    matches = re.match(r"https:\/\/github.com\/([^\/]*)\/([^\/]*)", self.repo_url)
    if matches:
      self.user_name = matches.groups(1)[0]
      self.repo_name = matches.groups(1)[1]
    else:
      self.user_name = None
      self.repo_name = None
    #log( 'self.user_name', 'console' )
    #log( self.user_name, 'console' )
    #log( 'self.repo_name', 'console' )
    #log( self.repo_name, 'console' )
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
    """Use the interview url to get the user's Playground id."""
    # Can probably do both in one match, but maybe we want to get granular with
    # our error messages...?
    server_match = re.match( r"^(.+)\/interview\?i=docassemble\.playground", self.playground_url)
    if server_match is None:
      self.server_url = None
    else:
      self.server_url = server_match.group(1)
      
    id_match = re.match( r"^.+(?:interview\?i=docassemble\.playground)(\d+)(?:.*)$", self.playground_url )
    if id_match is None:
      self.playground_id = None
    else:
      self.playground_id = id_match.group(1)
    
    return self
  
  def create_branch( self ):
    # get the name of the default branch
    # https://stackoverflow.com/a/16501903/14144258
    repo_url = self.github_repo_base
    repo_response = requests.request("GET", repo_url, data="", headers={})
    repo_json = json.loads( repo_response.text )
    self.default_branch = repo_json[ 'default_branch' ]
    #log( 'self.default_branch', 'console' )
    #log( self.default_branch, 'console' )
    default_branch_search = "refs/heads/" + self.default_branch
    
    # https://stackoverflow.com/questions/9506181/github-api-create-branch
    # Get refs and shas of all branches
    heads_url = self.github_repo_base + "/git/refs/heads"
    heads_response = requests.request("GET", heads_url, data="", headers={})
    heads_json = json.loads( heads_response.text )
    #log( 'heads_json', 'console' )
    #log( heads_json, 'console' )
    
    # Pick the default branch
    default_branch_data = {}
    for branch_data in heads_json:
      #log( 'branch_data', 'console' )
      #log( branch_data, 'console' )
      if branch_data[ "ref" ] == default_branch_search:
        default_branch_data = branch_data
    
    # Make a branch off of that (TODO: allow pushing to default branch if desired)
    base_sha = default_branch_data[ "object" ][ "sha" ]
    # Why can't I do this in `init()`?
    self.new_ref = "refs/heads/automated_testing_2"  # name of new branch
    post_payload = '{"ref":"' + self.new_ref + '","sha":"' + base_sha + '"}'
    post_url = self.github_repo_base + "/git/refs"
    post_headers = {
      'Accept': "application/vnd.github.v3+json",
      'Authorization': self.basic_auth,
    }
    post_response = requests.request("POST", post_url, data=post_payload, headers=post_headers)
    log( 'post_response.text', 'console' )
    log( post_response.text, 'console' )
    if post_response.status_code == 422:
      # If the branch name is already taken
      log( 'branch name taken', 'console' )
      count = 1
      ref = ''
      while ( post_response.status_code >= 300 and count < 20 ):
        # Add to the name of the branch until we get a unique one
        ref = self.new_ref + '_' + str( count )
        log( 'ref', 'console' )
        log( ref, 'console' )
        post_payload = '{"ref":"' + ref + '","sha":"' + base_sha + '"}'
        post_response = requests.request("POST", post_url, data=post_payload, headers=post_headers)
        log( 'post_response.text', 'console' )
        log( post_response.text, 'console' )
        count += 1
        
      if post_response.status_code == 422:
        # If the response is still a "reference already exists" error
        # Tell the user to delete old branches
        installer.error = 422
        return
      
      # Otherwise carry on
      self.new_ref = ref
      
    # Need these to make commits to this branch in the future
    
    return self
  
  def create_file( self ):
    # https://docs.github.com/en/rest/reference/repos#create-or-update-file-contents
    # https://docs.github.com/en/rest/reference/repos#contents
    # https://stackoverflow.com/questions/20045572/create-folder-using-github-api
    # https://stackoverflow.com/questions/22312545/github-api-to-create-a-file
    
    # Create a commit?
    # https://docs.github.com/en/rest/reference/git#list-matching-references
    
    # Check mergability of a PR
    # https://docs.github.com/en/rest/guides/getting-started-with-the-git-database-api#checking-mergeability-of-pull-requests
    return self
#
#  def get_files( self ):
#    # We have the files in the templates folder
#    # though the hidden files are... invisible...
#    # and the .feature file is uneditable...
#    pass
#
#  def transform_files( self ):
#    # Don't need this as Mako does the job
#    pass
#
#  def push_to_new_branch( self ):
#    pass
#
#  def make_pull_request( self ):
#    pass
