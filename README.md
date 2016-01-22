# OpenAM Scope Validators

This project is a plugin for OpenAM that allows you to access interesting information from a users underlying Identity to be associated with a token.

OpenAM provides a simple mechanism for this.

Currently there is just one custom validator, the RoleBasedAccessScopeValidator which exposes underlying groups in OpenAM as a "roles" scope, along with other interesting information about the user such as their display name.

