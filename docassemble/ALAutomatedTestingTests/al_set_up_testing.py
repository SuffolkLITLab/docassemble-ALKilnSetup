from github import Github  # PyGithub
from github import PublicKey
import requests
from nacl import encoding, public  # pynacl
# TODO: Reduce to just one encryption library :/
import codecs
from base64 import b64encode
import re
import json
from docassemble.base.util import log, value
from docassemble.base.core import DAObject

# reference:
# Mostly: https://pygithub.readthedocs.io/en/latest/introduction.html

class TestInstaller(DAObject):
  # In da `init` is the initializing function, NOT python's __init__
  def init( self, *pargs, **kwargs ):
    self.default_branch_name = "automated_testing"
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
      error = ErrorLikeObject( message='Interview URL', details=self.da_url_error )
      self.errors.append( error )
      log( error.__dict__, 'console' )
    
    # TODO: Is it possible to try to log into their server to
    # make sure they've given the correct information?
    return self
  

  ##########################
  # github: verify existance and auth, set values needed for future operations
  ##########################
  def set_github_auth( self ):
    """Get and set all the information needed to authorize to
    GitHub and handle all possible errors."""
    # Start clean. Other errors should have been handled already.
    self.errors = []
    
    # Check token credentials
    self.github = Github( self.token )
    user = self.github.get_user()
    try:
      self.user_name = user.login
    except Exception as error1:
      # github.GithubException.BadCredentialsException (401, 403)
      log( error1.__dict__, 'console' )
      self.user_name = ''
      error1.data[ 'details' ] = self.github_token_error
      self.errors.append( error1 )
    
    # If wants to do any repo stuff. Also defines self.owner_name if it's not defined already.
    if value( 'wants_to_set_repo_secrets' ) or value( 'wants_to_set_up_tests' ):
      self.repo = self.get_repo( self.repo_url )
      if self.repo:
        is_valid_collaborator = self.is_repo_collaborator()
        self.is_repo_admin()
    
    # Set org secrets
    is_valid_org_admin = False
    if ( value( 'wants_to_set_org_secrets' )):
      self.org = self.get_org()
      if self.org and user:
        is_valid_org_admin = self.is_valid_org_admin( user, self.org.login )
        
    #has_valid_min_repo_permissions = False
    #if value( 'wants_to_set_repo_secrets' ):  #
    #  if self.validate_repo():
    #    if self.validate_repo_collaborator_auth()  # Minimum permissions required
    #      has_valid_min_repo_permissions = True
    #
    #if has_valid_min_repo_permissions and value( 'wants_to_set_repo_secrets' ):
    #  if self.validate_repo_admin_auth():
    #    # Set repo secrets
    #    pass
      
    ## Check if repo exists
    #self.set_github_info_from_repo_url()
    #self.repo = self.get_repo()
    #
    #if self.repo:
    #  has_access = self.is_repo_collaborator()
    #  # TODO: Allow user to pick a custom branch name or to push to default branch
    #  self.branch_name = self.get_free_branch_name()
    #
    ## Give as many errors at once as is possible
    #if len( self.errors ) > 0:
    #  return self
    
    return self
  
  def get_org( self ):
    """Return org if it exists, otherwise None."""
    # Check if org exists
    try:
      # Trigger for authentication error or feedback for the user
      org = self.github.get_organization( self.owner_name )
    except Exception as error1:
      # UnknownObjectException: 404 {"message": "Not Found", "documentation_url": "https://docs.github.com/rest/reference/orgs#get-an-organization"}
      org = None
      log( error1.__dict__, 'console' )
      error1.data[ 'details' ] = self.org_does_not_exist_error
      self.errors.append( error1 )
    
    return org
    
  def is_valid_org_admin( self, user, org_name ):
    """Make sure org auth information is valid."""
    valid = True
    # Check if user belongs to org
    try:
      membership = user.get_organization_membership( org_name )
      role = membership.role
    except Exception as error2:
      valid = False
      role = None
      log( error2.__dict__, 'console' )
      error2.data[ 'details' ] = self.not_an_org_member_error
      self.errors.append( error2 )

    # Check if user is admin of org
    if role != 'admin':
      valid = False
      # Show error
      error3 = ErrorLikeObject( message='Not an admin', details=self.not_org_admin_error )
      log( error3.__dict__, 'console' )
      self.errors.append( error3 )
    
    return valid
  
  def get_repo( self, repo_url ):
    """Get repo obj of given repo. Make sure repo exists."""
    self.owner_name, self.repo_name, self.package_name = self.get_github_info_from_repo_url( repo_url )
    
    repo = None
    if self.repo_name:
      # Check if repo exists
      try:
        repo = self.github.get_repo( self.owner_name + '/' + self.repo_name )
      except Exception as error2:
        # github.GithubException.UnknownObjectException (404)
        log( error2.__dict__, 'console' )
        repo = None
        error2.data[ 'details' ] = self.github_repo_not_found_error
        self.errors.append( error2 )
        
    return repo
  
  def get_github_info_from_repo_url( self, repo_url ):
    """Use repo address to parse out owner name and repo name."""
    # Match either the actual URL or the clone HTTP or SSH URL
    matches = re.match( r"^.*github.com(?:\/|:)([^\/]*)\/?([^\/.]*)?(?:\..{3})?", repo_url )
    if matches:
      owner_name = matches.group(1)
      repo_name = matches.group(2)
      package_name = re.sub( r'docassemble-', '', repo_name )
    else:
      owner_name = ''
      repo_name = ''
      package_name = ''
      # Show error
      error = ErrorLikeObject( message='GitHub URL', details=self.github_url_error )
      self.errors.append( error )
      log( error.__dict__, 'console' )
      
    return [ owner_name, repo_name, package_name ]

  def is_repo_collaborator( self ):
    """Return True if user has collaborator access to the repo, else False and add error (403)"""
    has_access = self.repo.has_in_collaborators( self.user_name )
    if not has_access:
      error4 = ErrorLikeObject( message='Must have push access', details=self.github_access_error )
      self.errors.append( error4 )
      log( error4.__dict__, 'console' )
    return has_access
  
  def is_repo_admin( self ):
    "Check that user is admin of repo."
    role = self.repo.get_collaborator_permission( self.user_name )
    if role != 'admin':
      # Show error
      error3 = ErrorLikeObject( message='Not an admin', details=self.not_org_admin_error )
      log( error3.__dict__, 'console' )
      self.errors.append( error3 )
    
    return role != 'admin'
  
  def get_free_branch_name( self ):
    """Return str of valid avialable branch name or None. Add appropriate errors."""
    branch_name = None
    # Get all branches
    all_branches = self.repo.get_branches()
    
    # Control how many times the loop will run
    count = 0
    max_count = 20
    found_free_name = False  # Start the loop off correctly
    branch_name_base = self.default_branch_name
    branch_name = branch_name_base
    # Try every permitted new branch name until one is free
    while ( not found_free_name and count < max_count ):
      count += 1  # Ensure no infinite loop
      
      found_free_name = True  # The name is free until proven otherwise
      for existing_branch in all_branches:
        existing_branch_name = existing_branch.name
        # If branch already exists
        if existing_branch_name == branch_name:
          # Prep for next attempt
          found_free_name = False
          branch_name = branch_name_base + '_' + str( count )

    if not found_free_name:
      error3 = ErrorLikeObject( message='Branch already exists', details=self.github_branch_name_error )
      log( error3.__dict__, 'console' )
      branch_name = None
      self.errors.append( error3 )
    
    return branch_name
  

  ###############################
  # github: set secrets and create files
  # All checks should have passed at this point
  ###############################
  def update_github( self ):
    """Update github with what it needs and make a PR."""
    self.create_secrets()
    #self.make_new_branch()
    #self.push_files()
    #self.make_pull_request()
    return self
  
  def create_secrets( self ):
    """Set the GitHub repo secrets the tests need to log into the da server and
    create projects to contain the interviews being tested. TODO: use PyGithub's secret handling https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html?highlight=secret#github.Repository.Repository.create_secret. Org scope still missing: https://github.com/PyGithub/PyGithub/issues/1373#issuecomment-856616652."""
    self.put_secret( 'SERVER_URL', self.server_url )
    self.put_secret( 'PLAYGROUND_EMAIL', self.email )
    self.put_secret( 'PLAYGROUND_PASSWORD', self.password )
    self.put_secret( 'PLAYGROUND_ID', self.playground_id )
    return self
  
  def put_secret( self, secret_name, secret_value ):
    """Add or update one secret to the GitHub repo."""
    # Encryption by hand in case the lib gets discontinued: https://gist.github.com/plocket/af03ac9326b2ae6d36c937b125b2ea0a
    # Create repo secret: https://docs.github.com/en/rest/reference/actions#create-or-update-a-repository-secret
    
    if value('wants_to_set_org_secrets'):
      # No PyGithub secrets for org yet
      # by hand: https://github.com/PyGithub/PyGithub/blob/master/github/PublicKey.py#L39-L44
      # https://github.com/PyGithub/PyGithub/blob/master/github/Repository.py#L1420-L1438
      # https://pygithub.readthedocs.io/en/latest/github_objects/PublicKey.html
      headers1, data = self.org._requester.requestJsonAndCheck(
        "GET", f"{ self.org.url }/actions/secrets/public-key"
      )
      public_key = PublicKey.PublicKey( self.org._requester, headers1, data, completed=True )
      payload = public_key.encrypt( secret_value )
      put_parameters = {
        "key_id": public_key.key_id,
        "encrypted_value": payload,
        "visibility": "all",
      }
      status, headers, data = self.org._requester.requestJson(
        "PUT", f"{ self.org.url }/actions/secrets/{ secret_name }", input=put_parameters
      )
      
    elif value('wants_to_set_repo_secrets'):
      self.repo.create_secret( secret_name, secret_value )
    
    return self
  
  def make_new_branch( self ):
    """Create new branch off the default branch."""
    # Get default branch
    repo = self.repo
    default_branch_name = repo.default_branch
    default_branch = repo.get_branch( default_branch_name )
    # Make new branch off of default branch
    ref_path = "refs/heads/" + self.branch_name
    response = repo.create_git_ref( ref_path, default_branch.commit.sha )
    
    return self
  
  def push_files( self ):
    """Send files to folders in new branch in github.
    https://pygithub.readthedocs.io/en/latest/examples/Repository.html#create-a-new-file-in-the-repository'''
    # https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.create_file"""
    test_path = 'docassemble/' + self.package_name + '/data/sources/example_test.feature'
    test_commit_message = 'Add ' + test_path
    self.send_file( test_path, test_commit_message, self.example_test_str )  # 2
    self.send_file( '.env_example', 'Add .env_example', self.env_example_str )  # 1
    self.send_file( '.gitignore', 'Add .gitignore', self.gitignore_str )  # 3
    self.send_file( 'package.json', 'Add package.json', self.package_json_str )  # 4
    self.send_file( '.github/workflows/run_form_tests.yml', 'Add github/workflows/run_form_tests.yml', self.run_form_tests_str )  # 5
    return self
  
  def send_file( self, path, msg, contents ):
    '''Either create a new file or update an existing file with the given data.
       See https://stackoverflow.com/a/66673303/14144258.
       TODO: Discuss removing `self` to make it data-based.
       TODO: Shall we include the committer's user name, etc?'''
    try:
      # Try to create the file
      self.repo.create_file( path, msg, contents, branch=self.branch_name )
    except Exception as error:
      # If a file already exists, update that file instead
      if error.status == 422:
        file = self.repo.get_contents( path )
        self.repo.update_file( path, msg, contents, file.sha, branch=self.branch_name )
      else:
        # An undefined variable will make this error invisible as
        # da has a special way of dealing with those.
        raise error
    
    return self;
  
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
- [x] .github/workflows/run_form_tests.yml
'''  # TODO: Add issue # if desired
    response = self.repo.create_pull(base=base_name, head=head_name, title=title, body=description)
    self.pull_url = response.html_url
    
    return self


# Error helpers
class ErrorLikeObject():
  """Create object to match PyGithub data structure for errors."""
  def __init__( self, status=0, message='', details='' ):
    self.status = status
    self.data = { 'message': message, 'details': details }
