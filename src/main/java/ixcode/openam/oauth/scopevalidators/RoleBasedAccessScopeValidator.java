/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * <p/>
 * Copyright (c) 2014 ForgeRock AS. All Rights Reserved
 * <p/>
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 * <p/>
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 * <p/>
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 */

package ixcode.openam.oauth.scopevalidators;

import ixcode.openam.oauth.scopevalidators.domain.Group;
import ixcode.openam.oauth.scopevalidators.domain.Identity;
import ixcode.openam.oauth.scopevalidators.domain.IdentityRepository;
import ixcode.openam.oauth.scopevalidators.domain.Scopes;
import org.forgerock.oauth2.core.*;
import org.forgerock.openam.oauth2.IdentityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;

import static ixcode.openam.oauth.scopevalidators.RoleBasedAccessScopeValidator.RoleBasedScopeNames.*;
import static java.lang.String.format;

/**
 * See https://github.com/OpenRock/OpenAM/blob/master/openam-oauth2/src/main/java/org/forgerock/openam/oauth2/OpenAMScopeValidator.java
 * and DefaultOpenAMScopeValidator in this project For inspiration.
 * <p/>
 * Set this [ixcode.openam.oauth.scopevalidators.RoleBasedAccessScopeValidator] In your OAuth settings in openam
 * <p/>
 * This is in AccessControl -> Realm -> Services -> Oauth2Provider
 */
public class RoleBasedAccessScopeValidator extends AbstractScopeValidator {


    public enum RoleBasedScopeNames implements Scopes.ScopeName {
        username, display_name, email, roles;
    }


    private static final Logger LOG = LoggerFactory.getLogger(RoleBasedAccessScopeValidator.class);

    private final IdentityRepository identityRepository;


    @Inject
    public RoleBasedAccessScopeValidator(IdentityManager identityManager) {
        identityRepository = new IdentityRepository(identityManager);
    }

    /**
     * Set read and write permissions according to scope.
     *
     * @param token The access token presented for validation.
     * @return The map of read and write permissions,
     * with permissions set to {@code true} or {@code false},
     * as appropriate.
     * @TODO - Work out how to enable logging properly so we can use Log4J debug instead of sout
     */
    @Override
    protected Map<String, Object> mapScopes(AccessToken token) {
        Scopes availableScopes = new Scopes();

        try {
            Identity id = identityRepository.get(token);

            System.out.println(id.toString());

            availableScopes.put(username, id.uid());
            availableScopes.put(display_name, id.cn());
            availableScopes.put(email, id.mail());

            Set<String> groupIds = new HashSet<String>();
            for (Group group : id.getGroups()) {
                groupIds.add(group.cn());
            }

            System.out.println("ROLES: " + groupIds);
            availableScopes.put(roles, groupIds);

        } catch (Throwable t) {
            throw new RuntimeException("Unable to retrieve identity information! (See Cause)", t);
        }

        return availableScopes.filterOnRequestedScopes(token.getScope());
    }




}
