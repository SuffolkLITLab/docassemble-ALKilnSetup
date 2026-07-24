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

# ALKilnland
# ALKilnland/docassemble-OrgRepoWithMember
# ALKilnland/docassemble-OrgRepoWithReadOnlyMembers
# ALKilnland/docassemble-OrgRepoWithNoMembers
# alkilnert
# alkilnert/docassemble-SoleRepoWithReadOnlyCollaborator
# alkilnert/docassemble-SoleRepoWithNoCollaborator
# alkilnert/docassemble-SoleRepoWithCollaborator

# Error screen id: show_errors

@org_repo @happy @row25
Scenario: Sandbox org admin
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I tap to continue
  And I get to any of the question ids ["final review"] with this data:
  | var | value |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | org_repo |
  | wants_more_PAT_info |  False |
  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
  | gh_org_holder_name | ALKilnland |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | False |
  | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
  | wants_workflow_files | True |
  | wants_feature_file | True |
  | interviews_to_test['choose_me_1.yml'] | True |
  | interviews_to_test['choose_me_2.yml'] | True |
  | is_ready | True |

@org_repo @happy @row26
Scenario: Sandbox org member
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "org_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN"
  And I tap to continue
  And I get to any of the question ids ["final review"] with this data:
  | var | value |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | org_repo |
  | wants_more_PAT_info |  |
  | installer.token | ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN |
  | gh_org_holder_name | ALKilnland |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | False |
  | gh_repo_holder_name | ALKilnland/docassemble-OrgRepoWithMember |
  | wants_workflow_files | True |
  | wants_feature_file | True |
  | interviews_to_test['choose_me_1.yml'] | True |
  | interviews_to_test['choose_me_2.yml'] | False |
  | is_ready | True |

@sole_repo @happy @row27
Scenario: Sandbox sole owner 2 files
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "sole_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I tap to continue
  And I get to any of the question ids ["final review"] with this data:
  | var | value |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | sole_repo |
  | wants_more_PAT_info |  |
  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | False |
  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
  | wants_workflow_files | True |
  | wants_feature_file | True |
  | interviews_to_test['choose_me_1.yml'] | True |
  | interviews_to_test['choose_me_2.yml'] | True |
  | is_ready | True |

@sole_repo @happy @row28
Scenario: Sandbox sole owner wkflw files
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "sole_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I tap to continue
  And I get to any of the question ids ["final review"] with this data:
  | var | value |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | sole_repo |
  | wants_more_PAT_info |  |
  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | False |
  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
  | wants_workflow_files | True |
  | wants_feature_file | False |
  | is_ready | True |

@sole_repo @happy @row29
Scenario: Sandbox sole owner feat files
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "sole_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
  And I tap to continue
  And I get to any of the question ids ["final review"] with this data:
  | var | value |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | sole_repo |
  | wants_more_PAT_info |  |
  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | False |
  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
  | wants_workflow_files | False |
  | wants_feature_file | True |
  | interviews_to_test['choose_me_1.yml'] | True |
  | interviews_to_test['choose_me_2.yml'] | True |
  | is_ready | True |

#@sole_repo @sad @row30
#Scenario: Invalid Sandbox sole owner wants 0 feat files
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 10
#  And I set the var "environments['sandbox']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "sole_repo"
#  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
#  And I tap to continue
#  And I get to any of the question ids ["final review"] with this data:
#  | var | value |
#  | which_secrets_to_pre_set['repo'] | False |
#  | which_secrets_to_pre_set['org'] | False |
#  | environments['sandbox'] | True |
#  | task_type | sole_repo |
#  | wants_more_PAT_info |  |
#  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
#  | wait_for_repos_list_warning | True |
#  | wants_custom_repo | False |
#  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
#  | wants_workflow_files | False |
#  | wants_feature_file | True |
#  | is_ready | True |

#@sole_repo @sad @row31
#Scenario: Invalid Sandbox sole owner wants 0 files at all
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 10
#  And I set the var "environments['sandbox']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "sole_repo"
#  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
#  And I tap to continue
#  And I get to any of the question ids ["final review"] with this data:
#  | var | value |
#  | which_secrets_to_pre_set['repo'] | False |
#  | which_secrets_to_pre_set['org'] | False |
#  | environments['sandbox'] | True |
#  | task_type | sole_repo |
#  | wants_more_PAT_info |  |
#  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
#  | wait_for_repos_list_warning | True |
#  | wants_custom_repo | False |
#  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
#  | wants_workflow_files | False |
#  | wants_feature_file | False |
#  | is_ready | True |

#@sole_repo @sad @row32
# invalid custom non-existant repo name
#Scenario: Invalid Sandbox custom non-existant repo name sole owner
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 10
#  And I set the var "environments['sandbox']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "sole_repo"
#  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN"
#  And I tap to continue
#  And I get to any of the question ids ["final review"] with this data:
#  | var | value |
#  | which_secrets_to_pre_set['repo'] | False |
#  | which_secrets_to_pre_set['org'] | False |
#  | environments['sandbox'] | True |
#  | task_type | sole_repo |
#  | wants_more_PAT_info |  |
#  | installer.token | ALKILN_ALKS_GH_ADMIN_WORKFLOW_TOKEN |
#  | wait_for_repos_list_warning | True |
#  | wants_custom_repo | True |
#  | gh_repo_holder_name | no-org/no-repo |

#@sole_repo @sad @row33
# invalid custom non-existant repo name
#Scenario: Invalid Sandbox custom non-existant repo name sole owner
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 10
#  And I set the var "environments['sandbox']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "sole_repo"
#  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN"
#  And I tap to continue
#  And I get to any of the question ids ["final review"] with this data:
#  | var | value |
#  | which_secrets_to_pre_set['repo'] | False |
#  | which_secrets_to_pre_set['org'] | False |
#  | environments['sandbox'] | True |
#  | task_type | sole_repo |
#  | wants_more_PAT_info |  |
#  | installer.token | ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN |
#  | wait_for_repos_list_warning | True |
#  | wants_custom_repo | True |
#  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithReadOnlyCollaborator |

@sole_repo @happy @row34
Scenario: Sandbox sole collab with valid custom repo
  And I start the interview at "main.yml&alks_test=true"
  And the max seconds for each Step is 10
  And I set the var "environments['sandbox']" to "True"
  And I tap to continue
  And I set the var "task_type" to "sole_repo"
  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN"
  And I tap to continue
  And I get to any of the question ids ["final review"] with this data:
  | var | value |
  | which_secrets_to_pre_set['repo'] | False |
  | which_secrets_to_pre_set['org'] | False |
  | environments['sandbox'] | True |
  | task_type | sole_repo |
  | wants_more_PAT_info |  |
  | installer.token | ALKILN_ALKS_GH_MEMBER_WORKFLOW_TOKEN |
  | wait_for_repos_list_warning | True |
  | wants_custom_repo | True |
  | gh_repo_holder_name | alkilnert/docassemble-SoleRepoWithCollaborator |
  | wants_workflow_files | False |
  | wants_feature_file | True |
  | interviews_to_test['choose_me_1.yml'] | True |
  | interviews_to_test['choose_me_2.yml'] | True |
  | is_ready | True |

#@sole_repo @sad @row35
# invalid custom non-existant repo name
#Scenario: Invalid Sandbox custom non-existant repo name sole owner
#  And I start the interview at "main.yml&alks_test=true"
#  And the max seconds for each Step is 10
#  And I set the var "environments['sandbox']" to "True"
#  And I tap to continue
#  And I set the var "task_type" to "sole_repo"
#  And I set the var "installer.token" to the GitHub secret "ALKILN_ALKS_GH_MEMBER_GIST_TOKEN"
#  And I tap to continue
#  And I get to any of the question ids ["final review"] with this data:
#  | var | value |
#  | which_secrets_to_pre_set['repo'] | False |
#  | which_secrets_to_pre_set['org'] | False |
#  | environments['sandbox'] | True |
#  | task_type | sole_repo |
#  | wants_more_PAT_info |  |
#  | installer.token | ALKILN_ALKS_GH_MEMBER_GIST_TOKEN |
