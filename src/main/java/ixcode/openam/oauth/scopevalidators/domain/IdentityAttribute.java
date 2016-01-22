package ixcode.openam.oauth.scopevalidators.domain;

import com.sun.identity.idm.AMIdentity;
import ixcode.openam.oauth.scopevalidators.RoleBasedAccessScopeValidator;

import java.util.Set;

import static java.lang.String.format;

public class IdentityAttribute {
    public static String attributeAsString(AMIdentity identity, String attributeName) {
        try {
            return attributeToString(identity.getAttribute(attributeName));
        } catch (Throwable t) {
            throw new RuntimeException(format("Unable to access identity attribute [%s] from identity [%s] (See Cause)", attributeName, identity), t);
        }
    }

    public static String attributeToString(Set attributeValues) {
        if (attributeValues.size() > 1) {
            System.out.println("WARNING!! " + RoleBasedAccessScopeValidator.class.getName() + " - unexpectedly there is more than one value for an attribute - " + attributeValues.toString());
        }
        return attributeValues.iterator().next().toString();
    }
}
