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
    self.server_url = self.server_url_input.rstrip('/')
    
    try:
      # https://docassemble.org/docs/api.html#user
      response = requests.get(self.server_url + '/api/user', params={ 'key': self.da_api_key })
      status = response.status_code
      if status == 403:
        # 403 “Access Denied”
        error = ErrorLikeObject( message='Server API Key', details=self.da_access_denied_error )
        self.errors.append( error )
      elif status == 400:
        # 400 “Error obtaining user information”
        error = ErrorLikeObject( message='Docassemble user info', details=self.da_user_info_error )
        self.errors.append( error )
      else:
        self.da_email = response.json()['email']
    except requests.exceptions.ConnectionError as err:
      # https://docs.python-requests.org/en/latest/user/quickstart/#errors-and-exceptions
      error = ErrorLikeObject( message='Server URL', details=self.da_server_url_error )
      self.errors.append( error )
    except requests.exceptions.Timeout as err:
      # https://docs.python-requests.org/en/latest/user/quickstart/#errors-and-exceptions
      error = ErrorLikeObject( message='Server took too long', details=self.da_server_timeout_error )
      self.errors.append( error )
    
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
    
    if self.user_name != '':
      self.has_right_scopes( self.github.oauth_scopes )
    
    # If wants to do any repo stuff. Also defines self.owner_name if it's not defined already.
    if value( 'secret_type_wanted' ) == 'repo' or value( 'wants_to_set_up_tests' ):
      self.repo = self.get_repo( self.repo_url )
      if self.repo:
        # TODO: Add branch name to confirmation page or final page?
        # TODO: Allow user to pick a custom branch name or to push to default branch?
        self.branch_name = self.get_free_branch_name()
        self.has_correct_permissions()
    
    # Auth for setting org secrets
    if ( value('secret_type_wanted') == 'org' ):
      self.org = self.get_org()
      if self.org and user:
        self.is_valid_org_admin( user, self.org.login )
    
    return self
  
  def has_right_scopes( self, scopes ):
    """Make sure the developer gave the token the right scopes"""
    # TODO: discuss: Really if just setting repo secrets, only need repo permissions, but do we want to make it that complicated/inconsistent?
    if value('secret_type_wanted') == 'org' and value('wants_to_set_up_tests'):
      has_scopes = "admin:org" in scopes and "workflow" in scopes and "repo" in scopes
    elif value('secret_type_wanted') == 'org' and not value('wants_to_set_up_tests'):
      has_scopes = "admin:org" in scopes
    else:
      has_scopes = "workflow" in scopes and "repo" in scopes
      
    if not has_scopes:
      error = ErrorLikeObject( message='Incorrect Personal Access Token scopes', details=self.github_pat_scopes_error )
      self.errors.append( error )
      
    return has_scopes
  
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
      
    return [ owner_name, repo_name, package_name ]

  def has_correct_permissions( self ):
    """Return True if user has at least write permissions to the repo, else False and add error."""
    has_permissions = False
    
    # Are they even on the collaborator list
    is_valid_collaborator = self.repo.has_in_collaborators( self.user_name )
    if not is_valid_collaborator:
      error1 = ErrorLikeObject( message='Must be a collaborator', details=self.not_collaborator_error )
      self.errors.append( error1 )
      
    else:
      # Do they have a permission level that allows writing (pushing, etc)
      correct_permissions = [ 'admin', 'maintain', 'write' ]
      self.permissions = self.repo.get_collaborator_permission( self.user_name )
      
      has_permissions = self.permissions in correct_permissions
      if not has_permissions:
        error2 = ErrorLikeObject( message='Must have "write" permissions', details=self.permissions_error )
        self.errors.append( error2 )
    
    return is_valid_collaborator
  
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
      self.errors.append( error3 )
    
    return valid
  
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
      branch_name = None
      self.errors.append( error3 )
    
    return branch_name
  

  ###############################
  # github: set secrets and create files
  # All checks should have passed at this point
  ###############################
  def update_github( self ):
    """If desired, set repo or org secrets. If desired, add test files to repo."""
    if value('secret_type_wanted') == 'org' or value('secret_type_wanted') == 'repo':
      self.create_secrets()
    if value( 'wants_to_set_up_tests' ):
      self.make_new_branch()
      self.push_files()
      self.make_pull_request()
    return self
  
  def create_secrets( self ):
    """Set the GitHub repo secrets the tests need to log into the da server and
    create projects to contain the interviews being tested."""

    # The URL of the server where the tests will be run.
    self.put_secret( 'SERVER_URL', self.server_url )
    # The docassemble API key of the account that runs the tests.
    self.put_secret( 'DOCASSEMBLE_DEVELOPER_API_KEY', self.da_api_key )

    return self
  
  def put_secret( self, secret_name, secret_value ):
    """Add or update one secret to the GitHub repo. """
    # Encryption by hand in case the lib gets discontinued: https://gist.github.com/plocket/af03ac9326b2ae6d36c937b125b2ea0a
    
    if value('secret_type_wanted') == 'org':
      # PyGithub org secrets still missing: https://github.com/PyGithub/PyGithub/issues/1373#issuecomment-856616652
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
      
    elif value('secret_type_wanted') == 'repo':
      # https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html?highlight=secret#github.Repository.Repository.create_secret
      self.repo.create_secret( secret_name, secret_value )
    
    return self
  
  def make_new_branch( self ):
    """Create new branch off the default branch."""
    # Get default branch
    repo = self.repo
    # Make new branch off of default branch
    default_branch = repo.get_branch( repo.default_branch )
    ref_path = "refs/heads/" + self.branch_name
    response = repo.create_git_ref( ref_path, default_branch.commit.sha )
    
    return self
  
  def get_question_file_names( self ):
    """Get the names of the files in the `questions` folder.
    See https://pygithub.readthedocs.io/en/latest/examples/Repository.html#get-all-of-the-contents-of-the-repository-recursively
    """
    
    # Get the path to the "questions" folder
    package_path = ""
    # Get the (only possible?) folder inside the "docassemble" folder
    contents = self.repo.get_contents(f"docassemble")
    for item in contents:
        if item.type == "dir":
            package_path = f"{ item.path }/data/questions"

    # Get the names of the files in the "questions" folder
    question_files = self.repo.get_contents( package_path )
    names = []
    for file in question_files:
      names.append([ file.name, file.name ])
    
    return names
  
  def push_files( self ):
    """Push each file to the new branch in github in the correct directory."""
    # Only push test file if they wanted it
    
    if len(self.test_files_wanted) > 0:
      test_path = 'docassemble/' + self.package_name + '/data/sources/interviews_run.feature'
      test_commit_message = 'Add ' + test_path + ' for ALKiln automated tests'
      self.send_file( test_path, test_commit_message, self.first_feature_file_str )
      
    # Push the mandatory file
    self.send_file( '.github/workflows/run_form_tests.yml', 'Add .github/workflows/run_form_tests.yml for ALKiln automated tests', self.run_form_tests_str )
    
    return self
  
  def send_file( self, path, msg, contents ):
    """Either create a new file or update an existing file with the given data
       and push it to new branch.
       See https://stackoverflow.com/a/66673303/14144258.
       TODO: Discuss removing `self` to make it data-based.
       TODO: Shall we remove the committer's user name/email?"""
    
    #https://pygithub.readthedocs.io/en/latest/examples/Repository.html#create-a-new-file-in-the-repository
    # https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.create_file
    try:
      # Try to create the file
      self.repo.create_file( path, msg, contents, branch=self.branch_name )
    except Exception as error:
      # If a file already exists, update that file instead
      if error.status == 422:
        file = self.repo.get_contents( path )
        self.repo.update_file( path, msg, contents, file.sha, branch=self.branch_name )
      else:
        # fyi, da will swallow an undefined variable name error
        raise error
    
    return self
  
  def make_pull_request( self ):
    """Make a pull request with the new branch with changed files.
    https://pygithub.readthedocs.io/en/latest/examples/PullRequest.html"""
    # TODO: Check mergability of a PR?
    base_name = self.repo.default_branch
    head_name = self.branch_name
    title = 'Add ALKiln automated tests'  # TODO: Add issue # if desired
    description = '''Added these files:'''
    if len(self.test_files_wanted) > 0:
      description += '''
- tests/features/interviews_run.feature'''
    description += '''
- .github/workflows/run_form_tests.yml

Want to disable the tests? See documentation for ALKiln tests at https://suffolklitlab.github.io/docassemble-AssemblyLine-documentation/docs/automated_integrated_testing.
'''
    response = self.repo.create_pull(base=base_name, head=head_name, title=title, body=description)
    self.pull_url = response.html_url
    
    return self


# Error helpers
class ErrorLikeObject():
  """Create object to match PyGithub data structure for errors."""
  def __init__( self, status=0, message='', details='' ):
    self.status = status
    self.data = { 'message': message, 'details': details }
    log( self.__dict__, 'console' )
