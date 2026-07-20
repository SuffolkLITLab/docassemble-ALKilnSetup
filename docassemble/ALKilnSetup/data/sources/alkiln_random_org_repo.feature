@sandbox
Feature: Manage sandbox tests

# ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN
# ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN
# ALKILN_ALKS_GH_ADMIN_GIST_TOKEN
# ALKILN_ALKS_GH_MEMBER_ADMINORG_TOKEN
# ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN
# ALKILN_ALKS_GH_MEMBER_GIST_TOKEN
# ALKILN_ALKS_GH_OUTSIDER_ADMINORG_TOKEN
# ALKILN_ALKS_GH_OUTSIDER_WORKFLOW_TOKEN
# ALKILN_ALKS_GH_OUTSIDER_GIST_TOKEN

# ALKilnland/docassemble-OrgRepoWithMember

# Start by generating randomized tests.
@sole_repo @happy
Scenario: Sandbox 1 placeholder name
  Given ALKiln will make 0 constrained random answers tests
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And ALKiln will reach "final review" with:
  | var | possible values |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | sole_repo |
  | wants_more_PAT_info | True;;False;;False;;False;; |
  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN;;ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN |
  | gh_org_holder_name | ALKilnland |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | True;;False;;False;;False;;False;; |
  | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
  | wants_workflow_files | True;;True;;True;;True;;False |
  | wants_feature_file | True;;True;;True;;True;;False |
  | interviews_to_test['choose_me_1.yml'] | True |
  | interviews_to_test['choose_me_2.yml'] | True;;False |
  | is_ready | True |
