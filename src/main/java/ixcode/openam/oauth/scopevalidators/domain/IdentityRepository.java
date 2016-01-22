package ixcode.openam.oauth.scopevalidators.domain;

import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.oauth2.IdentityManager;
import org.forgerock.openam.oauth2.OpenAMAccessToken;

public class IdentityRepository {

    private final IdentityManager identityManager;

    public IdentityRepository(IdentityManager identityManager) {
        if (identityManager == null) {
            throw new RuntimeException("No Identity Manager! Cannot proceed");
        }

        this.identityManager = identityManager;
    }

    public Identity get(AccessToken token) throws UnauthorizedClientException {

        return new Identity(identityManager.getResourceOwnerIdentity(
                token.getResourceOwnerId(),
                ((OpenAMAccessToken) token).getRealm()));
    }
}
