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

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import org.forgerock.oauth2.core.*;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.oauth2.IdentityManager;
import org.forgerock.openam.oauth2.OpenAMAccessToken;
import org.forgerock.openidconnect.OpenIDTokenIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;

import static com.sun.identity.idm.IdType.GROUP;

/**
 * See https://github.com/OpenRock/OpenAM/blob/master/openam-oauth2/src/main/java/org/forgerock/openam/oauth2/OpenAMScopeValidator.java
 * and DefaultOpenAMScopeValidator in this project For inspiration.
 * <p/>
 * Set this [ixcode.openam.oauth.scopevalidators.RoleBasedAccessScopeValidator] In your OAuth settings in openam
 * <p/>
 * This is in AccessControl -> Realm -> Services -> Oauth2Provider
 */
public class RoleBasedAccessScopeValidator implements ScopeValidator {

    Logger LOG = LoggerFactory.getLogger(RoleBasedAccessScopeValidator.class);

    private final IdentityManager identityManager;
    private final OpenIDTokenIssuer openIDTokenIssuer;
    private final OAuth2ProviderSettingsFactory providerSettingsFactory;

    @Inject
    public RoleBasedAccessScopeValidator(IdentityManager identityManager, OpenIDTokenIssuer openIDTokenIssuer,
                                         OAuth2ProviderSettingsFactory providerSettingsFactory) {
        this.identityManager = identityManager;
        this.openIDTokenIssuer = openIDTokenIssuer;
        this.providerSettingsFactory = providerSettingsFactory;
    }

    @Override
    public Set<String> validateAuthorizationScope(ClientRegistration clientRegistration,
                                                  Set<String> scope,
                                                  OAuth2Request oAuth2Request) throws InvalidScopeException, ServerException {
        if (scope == null || scope.isEmpty()) {
            return clientRegistration.getDefaultScopes();
        }

        Set<String> scopes = new HashSet<String>(
                clientRegistration.getAllowedScopes());
        scopes.retainAll(scope);
        return scopes;
    }

    @Override
    public Set<String> validateAccessTokenScope(
            ClientRegistration clientRegistration,
            Set<String> scope,
            OAuth2Request request) {
        if (scope == null || scope.isEmpty()) {
            return clientRegistration.getDefaultScopes();
        }

        Set<String> scopes = new HashSet<String>(
                clientRegistration.getAllowedScopes());
        scopes.retainAll(scope);
        return scopes;
    }

    @Override
    public Set<String> validateRefreshTokenScope(
            ClientRegistration clientRegistration,
            Set<String> requestedScope,
            Set<String> tokenScope,
            OAuth2Request request) {
        if (requestedScope == null || requestedScope.isEmpty()) {
            return tokenScope;
        }

        Set<String> scopes = new HashSet<String>(tokenScope);
        scopes.retainAll(requestedScope);
        return scopes;
    }

    /**
     * Set read and write permissions according to scope.
     *
     * @param token The access token presented for validation.
     * @return The map of read and write permissions,
     * with permissions set to {@code true} or {@code false},
     * as appropriate.
     *
     * @TODO - Work out how to enable logging properly so we can use Log4J debug instead of sout
     * @TODO - only put in the scopes that are asked for (see how scopes is unused)
     */
    private Map<String, Object> mapScopes(AccessToken token) {
        Set<String> scopes = token.getScope();
        Map<String, Object> responseScopes = new HashMap<String, Object>();

        try {
            AMIdentity id = identityManager.getResourceOwnerIdentity(
                    token.getResourceOwnerId(),
                    ((OpenAMAccessToken) token).getRealm());

            System.out.println("IDENTITY - [" + id.getClass().getName() + " " + id.toString());

            responseScopes.put("cn", id.getAttribute("cn"));
            responseScopes.put("uid", id.getAttribute("uid"));
            responseScopes.put("mail", id.getAttribute("mail"));

            Set<String> groupIds = new HashSet<String>();
            for (Iterator itr = id.getMemberships(GROUP).iterator(); itr.hasNext(); ) {
                AMIdentity group = (AMIdentity) itr.next();

                groupIds.add(attributeToString(group.getAttribute("cn")));
            }

            System.out.println("ROLES: " + groupIds);
            responseScopes.put("roles", groupIds);

        } catch (Throwable t) {
            throw new RuntimeException("Unable to retrieve identity information! (See Cause)", t);
        }





        return responseScopes;
    }

    private static String attributeToString(Set attributeValues) {
        if (attributeValues.size() > 1) {
            System.out.println("WARNING!! " + RoleBasedAccessScopeValidator.class.getName() + " - unexpectedly there is more than one value for an attribute - " + attributeValues.toString());
        }
        return attributeValues.iterator().next().toString();
    }

    private static void debugGroup(AMIdentity group) throws IdRepoException, SSOException {
        System.out.println("GROUP - [" + group.getClass().getName() + " " + group.toString() + "]");
        Map attr = group.getAttributes();
        System.out.println("Group Attributes:");
        for (Iterator<Map.Entry> itrAttr = attr.entrySet().iterator(); itrAttr.hasNext();) {
            Map.Entry entry = itrAttr.next();
            System.out.println(entry.getKey() + "=" + entry.getValue());
        }
    }

    private String populateWithIdentity(String response, AMIdentity id) throws IdRepoException, SSOException {
        Map m = id.getAttributes();

        Set<Map.Entry> entrySet = m.entrySet();


        Iterator itr = entrySet.iterator();
        while (itr.hasNext()) {
            Map.Entry entry = (Map.Entry) itr.next();
            response += entry.getKey() + "=" + entry.getValue() + ", ";

        }
        return response;
    }

    private String checkIdentityManager() {
        if (identityManager != null) {
            return identityManager.getClass().getName();
        } else {
            return "Identity manager was not injected.";
        }
    }

    @Override
    public Map<String, Object> getUserInfo(
            AccessToken token,
            OAuth2Request request)
            throws UnauthorizedClientException {
        Map<String, Object> response = mapScopes(token);
        response.put(OAuth2Constants.JWTTokenParams.SUB, token.getResourceOwnerId());


        return response;
    }

    @Override
    public Map<String, Object> evaluateScope(AccessToken token) {
        return mapScopes(token);
    }

    @Override
    public Map<String, String> additionalDataToReturnFromAuthorizeEndpoint(
            Map<String, Token> tokens,
            OAuth2Request request) {
        return new HashMap<String, String>(); // No special handling
    }

    @Override
    public void additionalDataToReturnFromTokenEndpoint(
            AccessToken token,
            OAuth2Request request)
            throws ServerException, InvalidClientException {
        // No special handling
    }
}
