OAuth2.0 Login Plugin
==================
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/oauth2-login.svg)](https://plugins.jenkins.io/oauth2-login)

A Jenkins plugin which lets you login to Jenkins with your OAuth2.0 account. Also allows you to restrict access
to accounts in a given Apps domain.

To use this plugin, you must obtain OAuth 2.0 credentials from the
your OAuth2.0 service platform. These don't need to belong to a special account,
or even one associated with the domain you want to restrict logins to.

Instructions to create the Client ID and Secret:

 1. Login to the your OAuth2.0 service platform.
 1. Create a new app
 1. The authorized redirect URLs should contain ${JENKINS_ROOT_URL}/securityRealm/finishLogin
 1. Enter the created Client ID and secret in the Security Realm Configuration


## Version history
For recent versions see [GitHub releases](https://github.com/v2less/oauth2-login-plugin/releases),
for versions prior to 1.5 see [the changelog](CHANGELOG.md).
