@gh_n_y_n_sandbox @org_repo
Feature: Manage github_n_you and sandbox tests

# Something small to confirm the combination doesn't break anything and produces both workflow files.

# ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN
# ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN
# ALKILN_ALKS_GH_ADMIN_GIST_TOKEN
# ALKILN_ALKS_GH_MEMBER_ADMINORG_TOKEN
# ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN
# ALKILN_ALKS_GH_MEMBER_GIST_TOKEN
# ALKILN_ALKS_GH_OUTSIDER_ADMINORG_TOKEN
# ALKILN_ALKS_GH_OUTSIDER_WORKFLOW_TOKEN
# ALKILN_ALKS_GH_OUTSIDER_GIST_TOKEN

# ALKilnland
# ALKilnland/docassemble-OrgRepoWithMember
# ALKilnland/docassemble-OrgRepoWithReadOnlyMembers
# ALKilnland/docassemble-OrgRepoWithNoMembers
# alkilnert
# alkilnert/docassemble-SoleRepoWithReadOnlyCollaborator
# alkilnert/docassemble-SoleRepoWithNoCollaborator
# alkilnert/docassemble-SoleRepoWithCollaborator

# Error screen id: show_errors

@happy @row36
Scenario: G_n_Y & sandbox files for org repo admin
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['org'] | True |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "installer.da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |
