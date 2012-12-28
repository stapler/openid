package org.kohsuke.stapler.openid.client;

import org.kohsuke.stapler.AttributeKey;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerFallback;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.message.AuthSuccess;

import java.io.IOException;

/**
 * Protects the delegated URL-bound object via OpenID.
 *
 * <p>
 * If the current request isn't authenticated, send the browser to OpenID authentication sequence
 * with https://jenkins-ci.org/
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class AuthenticationShell implements StaplerFallback {
    private final ConsumerManager manager;
    private final Object delegate;
    public final AttributeKey<AuthSuccess> key = AttributeKey.sessionScoped();

    public AuthenticationShell(Object delegate) throws ConsumerException {
        this.delegate = delegate;

        manager = new ConsumerManager();
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
    }

    public Object getStaplerFallback() {
        // authenticate the user if needed
        key.set(currentSession().authenticate());
        // then fall through
        return delegate;
    }

    /**
     * Maps the login session to URL.
     */
    public OpenIDSession getOpenid() {
        return currentSession();
    }

    private OpenIDSession currentSession() {
        StaplerRequest req = Stapler.getCurrentRequest();
        OpenIDSession o = OpenIDSession.KEY.get(req);
        if (o==null)
            try {
                OpenIDSession.KEY.set(req, o = new OpenIDSession(manager,
                        getClaimedIdentity(req), req.findAncestor(this).getUrl()+"/openid/"));
            } catch (OpenIDException e) {
                throw HttpResponses.error(e);
            } catch (IOException e) {
                throw HttpResponses.error(e);
            }
        return o;
    }

    /**
     * Returns the OpenID that our user is claiming (that we are going to validate.)
     * In the typical context where this is used, this normally returns a constant
     * (I don't know what the right term for this, but the generic OpenID identifier
     * that allows the user to select the actual identifier in the server.)
     */
    protected abstract String getClaimedIdentity(StaplerRequest request);
}
