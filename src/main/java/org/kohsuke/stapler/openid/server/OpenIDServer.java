package org.kohsuke.stapler.openid.server;

import org.kohsuke.stapler.AttributeKey;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerFallback;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerManager;

import java.net.URL;

/**
 * OpenID server that allows users to use their Jenkins identity as an OpenID.
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class OpenIDServer implements StaplerFallback {
    final ServerManager manager =new ServerManager();

    /**
     * The URL of this endpoint, like "http://foo:8080/"
     */
    public final URL address;

    // test client
    public final Client client = new Client();

    private final AttributeKey<Session> session = AttributeKey.sessionScoped();

    public OpenIDServer(URL address) {
        this.address = address;
        if (!address.toExternalForm().endsWith("/"))
            throw new IllegalStateException("URL must end with '/': "+address);
        manager.setSharedAssociations(new InMemoryServerAssociationStore());
        manager.setPrivateAssociations(new InMemoryServerAssociationStore());
        manager.setOPEndpointUrl(address+"entryPoint");
        // Can't set the expiration date. see http://code.google.com/p/openid4java/issues/detail?id=186
        // manager.setExpireIn((int)TimeUnit.DAYS.toSeconds(180));
    }

    public Session getStaplerFallback() {
        Session o = session.get();
        if (o==null)
            session.set(o=createSession());
        return o;
    }

    /**
     * Creates a new session object (called for each HTTP session, whenever we need to start the
     * new authentication sequence.)
     */
    protected abstract Session createSession();

    public HttpResponse doLogout() {
        session.set(null);
        return HttpResponses.ok();
    }
}
