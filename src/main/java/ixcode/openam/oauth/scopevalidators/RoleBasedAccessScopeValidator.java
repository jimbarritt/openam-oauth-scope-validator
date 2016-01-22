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
import com.sun.identity.idm.IdType;
import org.forgerock.oauth2.core.*;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.oauth2.IdentityManager;
import org.forgerock.openam.oauth2.OpenAMAccessToken;
import org.forgerock.openidconnect.OpenIDTokenIssuer;

import javax.inject.Inject;
import java.util.*;

public class RoleBasedAccessScopeValidator implements ScopeValidator {

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
     *         with permissions set to {@code true} or {@code false},
     *         as appropriate.
     */
    private Map<String, Object> mapScopes(AccessToken token) {
        String response = "Identity unavilable";
        try {
            response = "";
            AMIdentity id = identityManager.getResourceOwnerIdentity(
                    token.getResourceOwnerId(),
                    ((OpenAMAccessToken) token).getRealm());

            response = populateWithIdentity(response, id);

            Set groups = id.getMemberships(IdType.GROUP);

            for (Iterator itr = groups.iterator(); itr.hasNext(); ) {
                Object g = itr.next();
                response += "GROUP: " + g.toString() + " : " + g.getClass().getName();
            }

        } catch (Throwable t) {

        }


        Set<String> scopes = token.getScope();
        Map<String, Object> map = new HashMap<String, Object>();
        final String[] permissions = {"read", "write"};

        for (String scope : permissions) {
            if (scopes.contains(scope)) {
                map.put(scope, response);
            } else {
                map.put(scope, false);
            }
        }
        return map;
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
