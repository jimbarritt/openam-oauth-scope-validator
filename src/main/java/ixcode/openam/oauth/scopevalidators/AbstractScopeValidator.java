package ixcode.openam.oauth.scopevalidators;

import org.forgerock.oauth2.core.*;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class AbstractScopeValidator implements ScopeValidator {
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

    protected abstract Map<String, Object> mapScopes(AccessToken token);

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
