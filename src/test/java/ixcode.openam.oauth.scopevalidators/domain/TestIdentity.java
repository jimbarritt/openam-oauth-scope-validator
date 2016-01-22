package ixcode.openam.oauth.scopevalidators.domain;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.iplanet.sso.SSOTokenListener;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import org.junit.Test;

import java.net.InetAddress;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


public class TestIdentity {

    @Test
    public void loads_attributes_from_delegate() throws Exception {
        AMIdentity delegate = new AMIdentityStub();
        Identity id = new Identity(delegate);

        assertThat(id.uid(), is("uid"));
        assertThat(id.cn(), is("cn"));
        assertThat(id.mail(), is("mail"));

    }

    private static class AMIdentityStub extends AMIdentity {

        public AMIdentityStub() throws SSOException, IdRepoException {
            super(new SSOTokenStub());
        }

        @Override
        public Set getAttribute(String attrName) throws IdRepoException, SSOException {

            return new HashSet(asList(attrName));
        }
    }

    private static class SSOTokenStub implements SSOToken {

        @Override
        public Principal getPrincipal() throws SSOException {
            return null;
        }

        @Override
        public String getAuthType() throws SSOException {
            return null;
        }

        @Override
        public int getAuthLevel() throws SSOException {
            return 0;
        }

        @Override
        public InetAddress getIPAddress() throws SSOException {
            return null;
        }

        @Override
        public String getHostName() throws SSOException {
            return null;
        }

        @Override
        public long getTimeLeft() throws SSOException {
            return 0;
        }

        @Override
        public long getMaxSessionTime() throws SSOException {
            return 0;
        }

        @Override
        public long getIdleTime() throws SSOException {
            return 0;
        }

        @Override
        public long getMaxIdleTime() throws SSOException {
            return 0;
        }

        @Override
        public SSOTokenID getTokenID() {
            return null;
        }

        @Override
        public void setProperty(String s, String s1) throws SSOException {

        }

        @Override
        public String getProperty(String s) throws SSOException {
            return "id=demo,ou=user,dc=openam,dc=forgerock,dc=org";
        }

        @Override
        public String getProperty(String s, boolean b) throws SSOException {
            return null;
        }

        @Override
        public void addSSOTokenListener(SSOTokenListener ssoTokenListener) throws SSOException {

        }

        @Override
        public String encodeURL(String s) throws SSOException {
            return null;
        }

        @Override
        public boolean isTokenRestricted() throws SSOException {
            return false;
        }

        @Override
        public String dereferenceRestrictedTokenID(SSOToken ssoToken, String s) throws SSOException {
            return null;
        }
    }
}
