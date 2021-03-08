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
    self.errors = []  # Make set() instead?
    super().init(*pargs, **kwargs)
  
  def set_da_info( self ):
    """Use the interview url to get the user's Playground id."""
    # Start clean (idempotent for da's loops).
    self.errors = []
    # Can we get granular with error messages?
    server_match = re.match( r"^(http.+)\/interview\?i=docassemble\.playground(\d+).*$", self.playground_url )
    if server_match:
      # TODO: More fine-grained validation of this information?
      # What if one group matches and the other doesn't
      self.server_url = server_match.group(1)
      self.playground_id = server_match.group(2)
    else:
      self.server_url = ''
      self.playground_id = ''
      # Show error
      error = ErrorLikeObject( self.da_url_error )
      self.errors.append( error )
      log( error.__dict__, 'console' )
    
    # TODO: Is it possible to try to log into their server to
    # make sure they've given the correct information?
    return self
  
  def set_github_auth( self ):
    """Get and set all the information needed to authorize to GitHub"""
    # Start clean. Other errors should have been handled already.
    self.errors = []
    
    self.get_github_info_from_repo_url()
    self.github = Github( self.token )
    user = self.github.get_user()  # if no _login, token did not lead to user
    # Token doesn't auth: github.GithubException.BadCredentialsException (401, 403)
    try:
      # Trigger for authentication error or feedback for the user
      self.user_name = user.login
    except Exception as error:
      log( error.__dict__, 'console' )
      error.data[ 'details' ] = self.github_token_error
      self.errors.append( error )
      
    # Repo doesn't exist: github.GithubException.UnknownObjectException (404)
    try:
      self.repo = self.github.get_repo( self.owner_name + '/' + self.repo_name )
    except Exception as error:
      log( error.__dict__, 'console' )
      error.data[ 'details' ] = self.github_repo_not_found_error
      self.errors.append( error )
    
    # TODO: Check user permissions: https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.get_collaborator_permission
    #self.repo.get_collaborator_permission( self.user_name )
    
    # Give as many errors at once as is possible
    if len( self.errors ) > 0:
      return self
    
    self.set_auth_for_secrets()
    
    return self
  
  def update_github( self ):
    """Update github with what it needs and make a PR."""
    self.make_new_branch()
    self.push_files()
    self.make_pull_request()
    self.create_secrets()
    return self
  
  def get_github_info_from_repo_url( self ):
    """Use repo address to parse out owner name and repo name. Needs self.repo_url"""
    # Match either the actual URL or the clone HTTP or SSH URL
    matches = re.match( r"^.*github.com(?:\/|:)([^\/]*)\/?([^\/.]*)?(?:\..{3})?", self.repo_url )
    if matches:
      self.owner_name = matches.group(1)
      self.repo_name = matches.group(2)
    else:
      self.owner_name = ''
      self.repo_name = ''
      # Show error
      error = ErrorLikeObject( message='GitHub URL', details=self.github_url_error )
      self.errors.append( error )
      log( error.__dict__, 'console' )
      
    return self
  
  def set_auth_for_secrets( self ):
    """Separated to allow easier removal when library finally supports secrets"""
    # The below is only needed because PyGithub does not handle secrets
    # The value for the GitHub 'Authorization' key
    auth_bytes = codecs.encode(bytes( self.owner_name + ':' + self.token, 'utf8'), 'base64')
    self.basic_auth = 'Basic ' + auth_bytes.decode().strip()
    # The base url string needed for making requests to the repo.
    self.github_repo_base = "https://api.github.com/repos/" + self.owner_name + "/" + self.repo_name
    self.set_key_values()
    
    return self
  
  def set_key_values( self ):
    """Gets and sets GitHub key id for the repo for secrets"""
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
  
  def make_new_branch( self ):
    """Create new branch, trying to use a brand new name. https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.create_git_ref"""
    # Get default branch
    repo = self.repo
    default_branch_name = repo.default_branch
    default_branch = repo.get_branch( default_branch_name )
    
    count = 0
    max_count = 20
    branch_name_base = "automated_testing"
    self.branch_name = branch_name_base
    while ( count < max_count ):
      try:
        ref_path = "refs/heads/" + self.branch_name
        response = repo.create_git_ref( ref_path, default_branch.commit.sha )
        break
      except Exception as error:  # github.GithubException.GithubException
        # Check branch already exists here
        # Check permissions here? A bit late?
        count += 1 # Prep for next attempt
        self.branch_name = branch_name_base + '_' + str( count )
    
    # Must make this refreshable somehow so that if folks
    # have to delete some branches to get it to run, it will
    # try again.
    return self
  
  def push_files( self ):
    """Send files to folders in new branch in github.
    https://pygithub.readthedocs.io/en/latest/examples/Repository.html#create-a-new-file-in-the-repository'''
    # https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.create_file"""
    self.repo.create_file('.env_example', 'Add .env_example', self.env_example_str, branch=self.branch_name)  # 1
    self.repo.create_file('tests/features/example_test.feature', 'Add tests/features/example_test.feature', self.example_test_str, branch=self.branch_name)  # 2
    self.repo.create_file('.gitignore', 'Add .gitignore', self.gitignore_str, branch=self.branch_name)  # 3
    self.repo.create_file('package.json', 'Add package.json', self.package_json_str, branch=self.branch_name)  # 4
    self.repo.create_file('.github/workflow/run_form_tests.yml', 'Add r.github/workflow/run_form_tests.yml', self.run_form_tests_str, branch=self.branch_name)  # 5
    
    return self
  
  def make_pull_request( self ):
    """Make a pull request with the new branch with changed files.
    https://pygithub.readthedocs.io/en/latest/examples/PullRequest.html"""
    # TODO: Check mergability of a PR?
    base_name = self.repo.default_branch
    head_name = self.branch_name
    title = 'Update to automated tests'  # TODO: Add issue # if desired
    description = '''Updates:
- [x] .env_example
- [x] tests/features/example_test.feature
- [x] .gitignore
- [x] package.json
- [x] .github/workflow/run_form_tests.yml
'''  # TODO: Add issue # if desired
    response = self.repo.create_pull(base=base_name, head=head_name, title=title, body=description)
    self.pull_url = response.url
    
    return self
  
  def create_secrets( self ):
    """Set the GitHub repo secrets the tests need to log into the da server and
    create projects to contain the interviews being tested. PyGithub does not yet handle secrets. See issue: https://github.com/PyGithub/PyGithub/issues/1373."""
    self.put_secret( 'PLAYGROUND_EMAIL', self.email )
    self.put_secret( 'PLAYGROUND_PASSWORD', self.password )
    self.put_secret( 'PLAYGROUND_ID', self.playground_id )
    return self
  
  def put_secret( self, name, value ):
    """Add or update one secret to the GitHub repo."""
    # Create repo secret: https://docs.github.com/en/rest/reference/actions#create-or-update-a-repository-secret
    # Convert the message and key to Uint8Array's (Buffer implements that interface)
    encrypted_key = public.PublicKey( self.public_key.encode("utf-8"), encoding.Base64Encoder() )
    sealed_box = public.SealedBox( encrypted_key )  # ?
    encrypted = sealed_box.encrypt( value.encode( "utf-8" ))  # LibSodium
    base64_encrypted = b64encode( encrypted ).decode( "utf-8" )  # turns into string
    
    url = self.github_repo_base + "/actions/secrets/" + name
    payload = '{"encrypted_value":"' + base64_encrypted + '", "key_id":"' + self.key_id + '"}'
    headers = {
      'Accept': "application/vnd.github.v3+json",
      'Authorization': self.basic_auth,
    }
    
    secret_put = requests.request( "PUT", url, data=payload, headers=headers )
    # Cannot check the value, but can check it exists
    secret_get = requests.request( "GET", url, data="", headers=headers )
    #log( response.text, 'console' )
    # TODO: create org secret: https://docs.github.com/en/rest/reference/actions#create-or-update-an-organization-secret
    
    return self


# handle errors
class ErrorLikeObject():
  """Create object to match PyGithub data structure for errors."""
  def __init__( self, status=0, message='', details='' ):
    self.status = status
    self.data = { 'message': message, 'details': details }
  