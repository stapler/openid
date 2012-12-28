package org.kohsuke.stapler.openid.client;

import org.openid4java.discovery.DiscoveryException;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
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

    public String getSRegAttribute(String attributeName) {
        try {
            if (!auth.hasExtension(SRegMessage.OPENID_NS_SREG)) return null;
            SRegResponse sr = (SRegResponse)auth.getExtension(SRegMessage.OPENID_NS_SREG);
            if (sr==null)   return null;
            return sr.getAttributeValue(attributeName);
        } catch (MessageException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getAxAttribute(String name) {
        try {
            if (!auth.hasExtension(AxMessage.OPENID_NS_AX)) return null;
            FetchResponse fr = (FetchResponse)auth.getExtension(AxMessage.OPENID_NS_AX);
            return fr.getAttributeValue(name);
        } catch (MessageException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Gets the nick name.
     */
    public String getNick() {
        String v = getSRegAttribute("nickname");
        if (v==null)
            v = getAxAttribute("http://axschema.org/namePerson/friendly");
        return v;
    }

    /**
     * Gets the e-mail address.
     */
    public String getEmail() {
        String v = getAxAttribute("http://axschema.org/contact/email");
        if (v==null)
            v = getAxAttribute("http://schema.openid.net/contact/email");
        return v;
    }

    /**
     * Gets the last name.
     */
    public String getLastName() {
        return getAxAttribute("http://axschema.org/namePerson/last");
    }

    /**
     * Gets the first name.
     */
    public String getFirstName() {
        return getAxAttribute("http://axschema.org/namePerson/first");
    }
}
