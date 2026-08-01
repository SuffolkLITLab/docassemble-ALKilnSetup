@gh_n_y
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

# Error screen id: show_errors

@happy @org_repo @row1
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
  And I get to any of the question ids ["tester account api key"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    # | wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    | secrets_to_pre_set['repo'] | True |
    | secrets_to_pre_set['org'] | True |
    | secrets_to_pre_set['None'] | False |
    | the_coveted_secrets['repo'] | True |
    | the_coveted_secrets['org'] | True |
    | covets_all_secrets | True |
    | will_test_on_this_server | True |
    # | server_url_input | https://apps-dev.suffolklitlab.org/ |
    # Change the below for all other tests
    | wants_more_API_key_info | True |
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

#@sad @org_repo @row2
#Scenario: Fail g_n_Y org repo da key 403
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I set the var "installer.token" to the GitHub secret ""
#  And I tap to continue
#
#@sad @org_repo @row3
#Scenario: Fail g_n_Y org repo da key 400
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I set the var "installer.token" to the GitHub secret ""
#  And I tap to continue
#
#@sad @org_repo @row4
#Scenario: Fail g_n_Y org repo da key 404
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I set the var "installer.token" to the GitHub secret ""
#  And I tap to continue
#
#@sad @org_repo @row5
#Scenario: Fail g_n_Y org repo da key other 400s?
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I set the var "installer.token" to the GitHub secret ""
#  And I tap to continue
#
#@sad @org_repo @row6
#Scenario: Fail g_n_Y org repo da key 500s?
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I set the var "installer.token" to the GitHub secret ""
#  And I tap to continue
#
#@sad @org_repo @row7
#Scenario: Fail g_n_Y org repo contradicts coveting both secrets
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 20
#  And I set the var "environments['github_n_you']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "org_repo"
#  And I set the var "wants_more_PAT_info" to "False"
#  And I set the var "installer.token" to the GitHub secret ""
#  And I tap to continue

@happy @org_repo @row8
Scenario: G_n_Y org repo admin with only repo secrets
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | True |
    | the_coveted_secrets['org'] | False |
    #| covets_all_secrets | True |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

# May repeat row 2, just avoiding error, which is a surface difference until we can test afterwards whether we actually set secrets
@happy @org_repo @row9
Scenario: G_n_Y org repo admin with only org secrets
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    # | wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | False |
    | the_coveted_secrets['org'] | True |
    # | covets_all_secrets | True |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

@happy @org_repo @row10
Scenario: G_n_Y org repo admin with no secrets
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    # | wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | False |
    | the_coveted_secrets['org'] | False |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

# @row11 low priority. repeats r1, just with non-da-repo, which is currently valid as of 2026/07/22. TODO: Transfer non-da-repo to other row.

@happy @org_repo @row12
Scenario: G_n_Y org repo member and writer
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_ADMINORG_TOKEN"
  And I get to any of the question ids ["github repo"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
  And I should NOT see the phrase "OrgRepoWithReadOnlyMembers"
  And I should NOT see the phrase "OrgRepoWithNoMembers"
  And I SHOULD see the phrase "OrgRepoWithMember"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    #| wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | True |
    # TODO: Check that this field is hidden
    #| the_coveted_secrets['org'] | False |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |
  And I take a screenshot
  And I tap to continue
  And I take a screenshot

# # Phrase assertion done by 12 now
# @medium @org_repo @row13
# Scenario: G_n_Y org member repo non-writer
#   And I start the interview at "main.yml&alks_test=true"
#   And the max seconds for each Step is 20
#   And I set the var "environments['github_n_you']" to "True"
#   And I tap to continue
#   And I set the var "task_type" to "org_repo"
#   And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN"
#   And I get to any of the question ids ["github repo"] with this data:
#     | gh_org_holder_name | ALKilnland |
#     | wait_for_repos_list_warning | True |
#   And I should NOT see the phrase "OrgRepoWithReadOnlyMembers"
#   And I should NOT see the phrase "OrgRepoWithNoMembers"
#   And I SHOULD see the phrase "OrgRepoWithMember"

@sad @org_repo @row14
Scenario: G_n_Y org repo member non-writing scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_GIST_TOKEN"
  And I tap to continue
      #And I get to any of the question ids ["show_errors"] with this data:
      #  | gh_org_holder_name | ALKilnland |
      #  | wait_for_repos_list_warning | True |
      #  # | wants_custom_repo | False |
      #  | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithReadOnlyMembers |
      #  #| secrets_to_pre_set['repo'] | False |
      #  #| secrets_to_pre_set['org'] | False |
      #  | secrets_to_pre_set['None'] | True |
  Then the question id SHOULD be "show_errors"
  And I take a screenshot

@happy @org_repo @row15
Scenario: G_n_Y org repo member non-org-secret scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | True |
    # TODO: Check that this field is hidden
    #| the_coveted_secrets['org'] | False |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

@happy @org_repo @row16
Scenario: G_n_Y org repo admin non-org-secret scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | True |
    # TODO: Check that this field is hidden
    #| the_coveted_secrets['org'] | False |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    | wants_workflow_files | True |
    | wants_feature_file | True |
    | interviews_to_test['choose_me_1.yml'] | True |
    | interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

