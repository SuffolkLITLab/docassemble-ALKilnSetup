@interviews_start
Feature: The interviews run without erroring

What specific behavior this file should test
[x] Each interview starts without an error
[x] Some example Steps are included that are commented out so they won't run

Made for ALKiln - a automated testing framework made in the Document Assembly Line Project.

Want to disable the tests? See ALKiln's docs: https://suffolklitlab.github.io/docassemble-AssemblyLine-documentation/docs/automated_integrated_testing

@alltests
Scenario: all_tests.yml runs
  #Given I wait 20 seconds
  Given I start the interview at "all_tests.yml"
  #And the maximum seconds for each Step in this scenario is 50
  #And I get to the question id "downloads" with this data:
  #  | var | value | trigger |
  #  | users[0].name.first | Uli | users[0].name.first |
  #  | users[0].name.last | User1 | users[0].name.first |
  
@testtrigger
Scenario: test_trigger.yml runs
  #Given I wait 20 seconds
  Given I start the interview at "test_trigger.yml"
  #And the maximum seconds for each Step in this scenario is 50
  #And I get to the question id "downloads" with this data:
  #  | var | value | trigger |
  #  | users[0].name.first | Uli | users[0].name.first |
  #  | users[0].name.last | User1 | users[0].name.first |
  
@urlargs
Scenario: url_args.yml runs
  #Given I wait 20 seconds
  Given I start the interview at "url_args.yml"
  #And the maximum seconds for each Step in this scenario is 50
  #And I get to the question id "downloads" with this data:
  #  | var | value | trigger |
  #  | users[0].name.first | Uli | users[0].name.first |
  #  | users[0].name.last | User1 | users[0].name.first |