@interviews_start
Feature: The interviews run without erroring

What specific behavior this file should test
[x] Each interview starts without an error
[x] Some example Steps are included that are commented out so they won't run

These tests are made to work with the ALKiln testing framework, an automated testing framework made under the Document Assembly Line Project.

Want to disable the tests? See ALKiln's docs: https://suffolklitlab.github.io/docassemble-AssemblyLine-documentation/docs/automated_integrated_testing

@alsetuptesting
Scenario: al_set_up_testing.yml runs
  #Given I wait 20 seconds
  Given I start the interview at "al_set_up_testing.yml"
  #And the maximum seconds for each Step in this scenario is 50
  #And I get to the question id "downloads" with this data:
  #  | var | value | trigger |
  #  | users[0].name.first | Uli | users[0].name.first |
  #  | users[0].name.last | User1 | users[0].name.first |