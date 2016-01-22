package ixcode.openam.oauth.scopevalidators.domain;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;

import java.util.Iterator;
import java.util.Map;

public class Group {

    public static Group asGroup(Object obj) {
        return new Group((AMIdentity)obj);
    }

    private final AMIdentity delegate;

    public Group(AMIdentity delegate) {
        this.delegate = delegate;
    }

    public String cn() {
        return IdentityAttribute.attributeAsString(delegate, "cn");
    }

    public static void debugGroup(AMIdentity group) throws IdRepoException, SSOException {
        System.out.println("GROUP - [" + group.getClass().getName() + " " + group.toString() + "]");
        Map attr = group.getAttributes();
        System.out.println("Group Attributes:");
        for (Iterator<Map.Entry> itrAttr = attr.entrySet().iterator(); itrAttr.hasNext(); ) {
            Map.Entry entry = itrAttr.next();
            System.out.println(entry.getKey() + "=" + entry.getValue());
        }
    }

}
