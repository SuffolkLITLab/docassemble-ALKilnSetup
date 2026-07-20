@gh_n_y @org_repo
Feature: Manage github_n_you tests for an org repo

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

@happy @row1
Scenario: G_n_Y org repo admin
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "wants_more_PAT_info" to "True"
  And I tap to continue
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  # And I get to any of the question ids ["da server info"] with this data:
  And I get to any of the question ids ["tester api key"] with this data:
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    # | wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    | which_secrets_to_pre_set['repo'] | False |
    | which_secrets_to_pre_set['org'] | True |
    | the_coveted_secrets['repo'] | True |
    | the_coveted_secrets['org'] | True |
    | covets_all_secrets | True |
    | will_test_on_this_server | True |
    # | installer.server_url_input | https://apps-dev.suffolklitlab.org/ |
    # Change the below for all other tests
    | wants_more_API_key_info | True |
  And I set the var "installer.da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

#@sad @row2
#Scenario: Fail g_n_Y org repo da key 403
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I tap to continue
#
#@sad @row3
#Scenario: Fail g_n_Y org repo da key 400
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I tap to continue
#
#@sad @row4
#Scenario: Fail g_n_Y org repo da key 404
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I tap to continue
#
#@sad @row5
#Scenario: Fail g_n_Y org repo da key other 400s?
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I tap to continue
#
#@sad @row6
#Scenario: Fail g_n_Y org repo da key 500s?
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I tap to continue
#
#@sad @row7
#Scenario: Fail g_n_Y org repo contradicts coveting both secrets
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I tap to continue

@happy @row8
Scenario: G_n_Y org repo admin with only repo secrets
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "wants_more_PAT_info" to "False"
  And I tap to continue
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  # And I get to any of the question ids ["da server info"] with this data:
  And I get to any of the question ids ["tester api key"] with this data:
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    # | wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    | which_secrets_to_pre_set['repo'] | False |
    | which_secrets_to_pre_set['org'] | True |
    | the_coveted_secrets['repo'] | True |
    | the_coveted_secrets['org'] | False |
    # | covets_all_secrets | True |
    | will_test_on_this_server | True |
    # | installer.server_url_input | https://apps-dev.suffolklitlab.org/ |
    # Change the below for all other tests
    | wants_more_API_key_info | False |
  And I set the var "installer.da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

@happy @row9
Scenario: G_n_Y org repo admin with only org secrets
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "wants_more_PAT_info" to "False"
  And I tap to continue
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  # And I get to any of the question ids ["da server info"] with this data:
  And I get to any of the question ids ["tester api key"] with this data:
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    # | wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    | which_secrets_to_pre_set['repo'] | False |
    | which_secrets_to_pre_set['org'] | True |
    | the_coveted_secrets['repo'] | False |
    | the_coveted_secrets['org'] | True |
    # | covets_all_secrets | True |
    | will_test_on_this_server | True |
    # | installer.server_url_input | https://apps-dev.suffolklitlab.org/ |
    # Change the below for all other tests
    | wants_more_API_key_info | False |
  And I set the var "installer.da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |






  
  # And I set the var "gh_org_holder_name" to "ALKilnland"
  # And I tap to continue
  # And I set the var "wait_for_repos_list_warning" to "True"
  # # And I set the var "wants_custom_repo" to "False"
  # And I set the var "gh_repo_holder_name" to "ALKilnland/docassemble-OrgRepoWithMember"
  # And I tap to continue
  # And I set the var "which_secrets_to_pre_set['repo']" to "False"
  # And I set the var "which_secrets_to_pre_set['org']" to "True"
  # the_coveted_secrets['repo']
  # the_coveted_secrets['org']
  # covets_all_secrets
  # will_test_on_this_server
  # # installer.server_url_input
  # wants_more_API_key_info
  # 
  # And I get to any of the question ids ["final review"] with this data:
  # | var | value |
  # | which_secrets_to_pre_set['repo'] | False |
  # | which_secrets_to_pre_set['org'] | False |
  # | environments['sandbox'] | True |
  # | task_type | org_repo |
  # | wants_more_PAT_info |  True |
  # | installer.token | ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN |
  # | gh_org_holder_name | ALKilnland |
  # | wait_for_repos_list_warning | True |
  # | wants_custom_repo | False |
  # | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
  # | wants_workflow_files | True |
  # | wants_feature_file | True |
  # | interviews_to_test['choose_me_1.yml'] | True |
  # | interviews_to_test['choose_me_2.yml'] | True |
  # | is_ready | True |

