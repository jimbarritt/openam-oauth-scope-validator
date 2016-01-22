# OpenAM Scope Validators

This project is a plugin for OpenAM that allows you to access interesting information from a users underlying Identity to be associated with a token.

OpenAM provides a simple mechanism for this.

Currently there is just one custom validator, the RoleBasedAccessScopeValidator which exposes underlying groups in OpenAM as a "roles" scope, along with other interesting information about the user such as their display name.

# Installation

It is important that this is built against the same version of of OpenAM that it is deployed against.

The master branch is set to 12.0.0-1 we will create alternate branches for other versions. 

Installation comes from https://backstage.forgerock.com/#!/docs/openam/12.0.0/dev-guide/chap-oauth2-scopes
                        
The default org.forgerock.openam.oauth2.OpenAMScopeValidator