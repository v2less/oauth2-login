CHANGELOG
=========

Known issues
------------

See the full list of issues at [JIRA](https://issues.jenkins-ci.org/issues/?filter=18451)

1.5 and newer
---
No longer tracked in this file. See [GitHub releases](https://github.com/jenkinsci/google-login-plugin/releases) instead.

1.4
-----
* Fix: [JENKINS-47274](https://issues.jenkins-ci.org/browse/JENKINS-47274) - Fire event after the user has been loaded from the Jenkins user management service ([#10](https://github.com/jenkinsci/google-login-plugin/pull/10))
* Fix: Set `hd` param value to `*` when configured with a list of Google Apps domains ([#11](https://github.com/jenkinsci/google-login-plugin/pull/11))
* Task: Add Jenkinsfile for ci.jenkins.io. ([#12](https://github.com/jenkinsci/google-login-plugin/pull/12))
* Fix: Remove leading and trailing spaces from domain ([#9](https://github.com/jenkinsci/google-login-plugin/pull/9))
* Fix: [JENKINS-36706](https://issues.jenkins-ci.org/browse/JENKINS-36706) - Improve session timeout handling ([#8](https://github.com/jenkinsci/google-login-plugin/pull/8))
* Task: Update parent POM. Raises Jenkins Core requirement to 2.60.1
* Task: fix findbugs issues
* Task: Update inline help based on latest Google Developers Console UI
* Fix: Avoid 'Committed' stacktraced in logs

1.3.1
-----
* Fix [security vulnerabilities](https://jenkins.io/security/advisory/2018-04-16/)

1.3
---
* Feature: Allow multiple domains separated by comma ([#3](https://github.com/jenkinsci/google-login-plugin/pull/3))
* Fix: [JENKINS-37749](https://issues.jenkins-ci.org/browse/JENKINS-37749) - Disable autocomplete on clientId and clientSecret
* Fix: [JENKINS-33286](https://issues.jenkins-ci.org/browse/JENKINS-33286) - Redirect to a logged out page

1.2.1
-----
* Fix: [JENKINS-30965](https://issues.jenkins-ci.org/browse/JENKINS-30965) - Error when browsing user configuration page.

1.2
---
* Fix: [SECURITY-208 - CVE-2015-5298](https://wiki.jenkins.io/display/SECURITY/Jenkins+Security+Advisory+2015-10-12) - The Google Login Plugin (versions 1.0 and 1.1) allows malicious anonymous users to authenticate successfully against Jenkins instances that are supposed to be locked down to a particular Google Apps domain through client-side request modification.
