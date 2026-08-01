@gh_n_y
Feature: Manage sole repos and org secrets for github_n_you tests

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

@happy @sole_repo @row17
Scenario: G_n_Y sole repo admin workflow scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "sole_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    #| gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithNoCollaborator |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | True |
    # Check this isn't visible
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

@happy @sole_repo @row18
Scenario: G_n_Y sole repo member workflow scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "sole_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    #| gh_org_holder_name | ALKilnland |
    | wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
    | the_coveted_secrets['repo'] | True |
    # Check this isn't visible
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

@happy @org_secrets @row19
Scenario: G_n_Y org secrets admin adminorg scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_secrets"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    #| wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    #| gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
  And I take a screenshot
  And I tap to continue
  # And I get to any of the question ids ["da server info"] with this data:
  #   | var | value |
  #   # I think/hope it'll skip this screen
  #   #| the_coveted_secrets['repo'] | True |
  #   # Check this isn't visible
  #   | the_coveted_secrets['org'] | False |
  And I set the var "will_test_on_this_server" to "True"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    #| wants_workflow_files | True |
    #| wants_feature_file | True |
    #| interviews_to_test['choose_me_1.yml'] | True |
    #| interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

@happy @org_secrets @row20
Scenario: G_n_Y org secrets custom server address
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_secrets"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    #| wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    #| gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
  And I take a screenshot
  And I tap to continue
  
  # And I get to any of the question ids ["da server info"] with this data:
  #   | var | value |
  #   # I think/hope it'll skip this screen
  #   #| the_coveted_secrets['repo'] | True |
  #   # Check this isn't visible
  #   | the_coveted_secrets['org'] | False |
  
  And I set the var "will_test_on_this_server" to "False"
  And I set the var "server_url_input" to "https://apps-dev.suffolklitlab.org"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I get to any of the question ids ["final review"] with this data:
    | var | value |
    #| wants_workflow_files | True |
    #| wants_feature_file | True |
    #| interviews_to_test['choose_me_1.yml'] | True |
    #| interviews_to_test['choose_me_2.yml'] | True |
    | is_ready | True |

@sad @org_secrets @row21
Scenario: Fail g_n_Y org secrets with non-da server url
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_secrets"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_ADMINORG_TOKEN"
  And I get to any of the question ids ["da server info"] with this data:
    | var | value |
    | gh_org_holder_name | ALKilnland |
    #| wait_for_repos_list_warning | True |
    #| wants_custom_repo | False |
    #| gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
    #| secrets_to_pre_set['repo'] | False |
    #| secrets_to_pre_set['org'] | False |
    | secrets_to_pre_set['None'] | True |
  And I take a screenshot
  And I tap to continue
  
  # And I get to any of the question ids ["da server info"] with this data:
  #   | var | value |
  #   # I think/hope it'll skip this screen
  #   #| the_coveted_secrets['repo'] | True |
  #   # Check this isn't visible
  #   | the_coveted_secrets['org'] | False |
  
  And I set the var "will_test_on_this_server" to "False"
  And I set the var "server_url_input" to "https://duckduckgo.com"
  And I set the var "da_api_key" to the GitHub secret "ALKILN_ALKS_VALID_DA_API_KEY"
  And I tap to continue
  And the question id SHOULD be "show_errors"
  And I take a screenshot

# # Not yet implemented (can't enter custom org name)
# @sad @org_secrets @row22
# Scenario: Fail with non-existant GitHub org as custom org

@sad @org_secrets @row23
Scenario: Fail g_n_Y org secrets only member
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_secrets"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_ADMINORG_TOKEN"
  And I tap to continue
  And the question id SHOULD be "show_errors"
  And I take a screenshot

@sad @org_secrets @row24
Scenario: Fail g_n_Y org secrets admin wrong scopes
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 20
  And I set the var "environments['github_n_you']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_secrets"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I tap to continue
  And the question id SHOULD be "show_errors"
  And I take a screenshot
