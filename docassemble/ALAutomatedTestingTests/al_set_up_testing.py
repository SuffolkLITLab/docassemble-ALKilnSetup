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
    server_match = re.match( r"^(http.+)\/interview\?i=docassemble\.playground(\d+).*$", self.playground_url )
    if server_match is None:
      self.server_url = None
      self.playground_id = None
      # TODO: Show error
    else:
      # TODO: More fine-grained validation of this information
      self.server_url = server_match.group(1)
      self.playground_id = server_match.group(2)
    
    # TODO: Is it possible to try to log into their server to
    # make sure they've given the correct information?
    return self
  
  # da auth and pushing
  def set_github_auth( self ):
    """Get and set all the information needed to authorize to GitHub"""
    self.get_github_info_from_repo_url()
    
    # TODO: detect types of errors
    
    self.github = Github( self.token )
    # Token doesn't auth: github.GithubException.BadCredentialsException (401, 403)
    user = self.github.get_user()
    # Repo doesn't exist: github.GithubException.UnknownObjectException (404)
    self.repo = user.get_repo( self.repo_name )
    self.owner_name = self.repo.owner.login
    self.user_name = self.github.get_user().login  # feedback for the user
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
    """Update github with what it needs and make a PR."""
    self.make_new_branch()
    self.push_files()
    self.make_pull_request()
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
  
  # handle errors
    