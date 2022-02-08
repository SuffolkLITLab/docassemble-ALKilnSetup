# ALKiln support package

Assembly Line Kiln (ALKiln) is a framework for automatically testing **any** [docassemble](https://docassemble.org/) package using GitHub. ALKiln is being developed as part of the SuffolkLITLab Document Assembly Line project. See [documentation for kiln](https://suffolklitlab.github.io/docassemble-AssemblyLine-documentation/docs/automated_integrated_testing).

This package supports ALKiln in different ways.

## Tool to set up testing

[Tap here to set up automated integrated testing for your docassemble interview](https://apps-dev.suffolklitlab.org/start/test-setup/).

This repo contains a step-by-step form that a developer can use to set up automated integrated testing for **any** docassemble package. It requires, among other things, a docassemble account and a temporary GitHub personal access token with correct permissions. It will add necessary GitHub secrets, make a new branch, push necessary files to that branch, and make a PR with that branch.

## Test ALKiln itself

This package provides files that the ALKiln testing framework can use to test its own functionality. That includes tests for setting different types of fields, for observing the state of the page, and for getting error messages.
