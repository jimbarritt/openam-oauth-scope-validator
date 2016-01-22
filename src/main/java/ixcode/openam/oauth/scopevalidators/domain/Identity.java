package ixcode.openam.oauth.scopevalidators.domain;

import com.sun.identity.idm.AMIdentity;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import static com.sun.identity.idm.IdType.GROUP;
import static ixcode.openam.oauth.scopevalidators.domain.Group.asGroup;
import static ixcode.openam.oauth.scopevalidators.domain.Identity.IdentityAttributeName.*;
import static ixcode.openam.oauth.scopevalidators.domain.IdentityAttribute.attributeAsString;
import static java.lang.String.format;

public class Identity {

    public enum IdentityAttributeName {
        uid, mail, cn
    }

    private final AMIdentity delegate;

    public Identity(AMIdentity delegate) {
        this.delegate = delegate;
    }

    public String toString() {
        return "IDENTITY - [" + delegate.getClass().getName() + " " + delegate.toString();
    }

    public Set<Group> getGroups() {
        try {
            Set<Group> groups = new HashSet<Group>();
            for (Iterator itr = delegate.getMemberships(GROUP).iterator(); itr.hasNext(); ) {
                groups.add(asGroup(itr.next()));
            }
            return groups;
        } catch (Exception e) {
            throw new RuntimeException(format("Could not get groups from identity [%s] (See Cause)", delegate), e);
        }
    }

    public String uid() {
        return attributeAsString(IdentityAttributeName.uid);
    }

    public String cn() {
        return attributeAsString(cn);
    }

    public String mail() {
        return attributeAsString(mail);
    }


    private String attributeAsString(IdentityAttributeName name) {
        return IdentityAttribute.attributeAsString(delegate, name.toString());
    }
}
