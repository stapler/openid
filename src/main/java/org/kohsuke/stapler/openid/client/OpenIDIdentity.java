package org.kohsuke.stapler.openid.client;

import org.openid4java.discovery.DiscoveryException;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;

/**
 * Verified identity of the user.
 *
 * @author Kohsuke Kawaguchi
 */
public class OpenIDIdentity {
    /**
     * Underlying openid4java authentication object that captures all the info.
     */
    private final AuthSuccess auth;

    public OpenIDIdentity(AuthSuccess auth) {
        this.auth = auth;
    }

    /**
     * Gets the fully OpenID URL of the user.
     */
    public String getOpenID() {
        try {
            return auth.getIdentity();
        } catch (DiscoveryException e) {
            throw new AssertionError(e);    // AFAICT, this can never be thrown
        }
    }

    /**
     * Gets the nick name.
     */
    public String getNick() {
        try {
            SRegResponse sr = (SRegResponse)auth.getExtension(SRegMessage.OPENID_NS_SREG);
            return sr.getAttributeValue("nickname");
        } catch (MessageException e) {
            throw new IllegalStateException(e);
        }
    }
}
