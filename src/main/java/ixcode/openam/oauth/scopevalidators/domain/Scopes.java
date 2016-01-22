package ixcode.openam.oauth.scopevalidators.domain;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Scopes {

    public interface ScopeName {
        String toString();
    }

    Map<String, Object> scopes = new HashMap<String, Object>();

    public void put(ScopeName name, Object value) {
        scopes.put(name.toString(), value);
    }


    public Map<String, Object> filterOnRequestedScopes(Set<String> requestedScopes) {
        Map<String, Object> responseScopes = new HashMap<String, Object>();

        for (String key : requestedScopes) {
            responseScopes.put(key, scopes.get(key));
        }
        return responseScopes;
    }


}
