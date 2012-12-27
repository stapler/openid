package org.kohsuke.stapler.openid.server;

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.association.AssociationException;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;
import org.openid4java.server.ServerException;
import org.openid4java.server.ServerManager;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Represents an in-flight OpenID authentication sequence.
 * <p>
 * For each user going through the OpenID protocol, one instance is created.
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class Session {
    public final OpenIDServer server;
    private final ServerManager manager;

    private ParameterList requestp;
    private String mode;
    private String realm;
    private String returnTo;

    /**
     * OpenID URL of this user.
     */
    private OpenIDIdentity identity;

    public Session(OpenIDServer server) {
        this.server = server;
        this.manager = server.manager;
    }

    /**
     * A string that represents the client who is requesting an authentication.
     * This is either the host name of the client, or in a rare case it is the "openid.realm" attribute.
     *
     * <p>
     * This value can be trusted, even though it came from the client.
     */
    public String getRealm() {
        return realm;
    }

    /**
     * URL to send the user back to, once the authentication is complete.
     */
    public String getReturnTo() {
        return returnTo;
    }

    /**
     * Returns the current user's identity.
     *
     * This is the same object that gets passed to {@link #authenticateUser(OpenIDIdentity)},
     * and is null until the authentication gets to that point.
     */
    public OpenIDIdentity getIdentity() {
        return identity;
    }

    /**
     * Landing page for the OpenID protocol.
     */
    public HttpResponse doEntryPoint(StaplerRequest request) throws IOException {
        // these are the invariants during the whole conversation
        requestp = new ParameterList(request.getParameterMap());
        mode = requestp.getParameterValue("openid.mode");
        realm = requestp.getParameterValue("openid.realm");
        returnTo = requestp.getParameterValue("openid.return_to");

        if (realm==null && returnTo!=null)
            try {
                realm = new URL(returnTo).getHost();
            } catch (MalformedURLException e) {
                realm = returnTo; // fall back
            }

        return handleRequest();
    }

    /**
     * When the protocol gets to the point of needing to authenticate the user on the server side,
     * this method is called.
     *
     * <p>
     * If the user needs to be redirected elsewhere for the server to authenticate (such as sending
     * him to the login page), this method can return a non-null object (for example see {@link HttpResponses#redirectViaContextPath(String)})
     * or throw an {@link HttpResponse} as an exception. The caller will use this
     * {@link HttpResponse} as a response to the client.
     * After such authentication, the {@link #handleRequest()} must be called to pick up the OpenID
     * dance where we left off.
     * <p>
     * If the user is already authenticated on the server side, then the {@link OpenIDIdentity} object
     * should be populated with the information about the user, and this method shall return null.
     * In this case, the protocol will continue.
     *
     * <p>
     * Another common practice is to verify with the user that he actually intended to login
     * to {@linkplain #getRealm() the realm} requesting authentication.
     */
    protected abstract HttpResponse authenticateUser(OpenIDIdentity id);

    public HttpResponse handleRequest() {
        try {
            if ("associate".equals(mode)) {
               // --- process an association request ---
                return new MessageResponse(manager.associationResponse(requestp));
            } else
            if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {
                // if the user hasn't logged in to us yet, this will make them do so
                HttpResponse r = authenticateUser(identity = new OpenIDIdentity());
                if (r!=null)        return r;

                String openId = identity.getOpenId(server);
                Message rsp = manager.authResponse(requestp, openId, openId, true);
                respondToFetchRequest(rsp);
                if (rsp instanceof  AuthSuccess) {
                    // Need to sign after because SReg extension parameters are signed by openid4java
                    try {
                        manager.sign((AuthSuccess)rsp);
                    } catch (ServerException e) {
                        throw HttpResponses.error(500, e);
                    } catch (AssociationException e) {
                        throw HttpResponses.error(500, e);
                    }
                }

                return HttpResponses.redirectTo(rsp.getDestinationUrl(true));
            } else if ("check_authentication".equals(mode)) {
                return new MessageResponse(manager.verify(requestp));
            } else {
                throw HttpResponses.error(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unknown request: " + mode);
            }
        } catch (MessageException e) {
            e.printStackTrace();
            throw HttpResponses.error(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e);
        }
    }

    /**
     * Responds to the fetch request by adding them.
     *
     * Java.net only gives us the ID, and everything else is just mechanically derived from it,
     * so there's no need to get the confirmation from users for passing them.
     */
    protected void respondToFetchRequest(Message rsp) throws MessageException {
        AuthRequest authReq = AuthRequest.createAuthRequest(requestp, manager.getRealmVerifier());
        if (authReq.hasExtension(AxMessage.OPENID_NS_AX)) {
            MessageExtension ext = authReq.getExtension(AxMessage.OPENID_NS_AX);
            if (ext instanceof FetchRequest) {
                FetchRequest fetchReq = (FetchRequest) ext;
                FetchResponse fr = FetchResponse.createFetchResponse();

                for (Map.Entry<String,String> e : ((Map<String,String>)fetchReq.getAttributes()).entrySet()) {
                    if (e.getValue().equals("http://axschema.org/contact/email")
                    ||  e.getValue().equals("http://schema.openid.net/contact/email"))
                        fr.addAttribute(e.getKey(),e.getValue(), identity.getEmail());
                    if (e.getValue().equals("http://axschema.org/namePerson/friendly"))
                        fr.addAttribute(e.getKey(),e.getValue(), identity.getNick());
                    if (e.getValue().equals("http://axschema.org/namePerson/first"))
                        fr.addAttribute(e.getKey(),e.getValue(), identity.getFirstName());
                    if (e.getValue().equals("http://axschema.org/namePerson/last"))
                        fr.addAttribute(e.getKey(),e.getValue(), identity.getLastName());
                    // TODO: we probably need to add more
                }

                rsp.addExtension(fr);
            }
        }
        if (authReq.hasExtension(SRegMessage.OPENID_NS_SREG)) {
            MessageExtension ext = authReq.getExtension(SRegMessage.OPENID_NS_SREG);
            if (ext instanceof SRegRequest) {
                SRegRequest req = (SRegRequest) ext;
                SRegResponse srsp = SRegResponse.createFetchResponse();

                for (String name : (List<String>)req.getAttributes()) {
                    if (name.equals("nickname"))
                        srsp.addAttribute(name,identity.getNick());
                    // TODO: we probably need to add more
                }

                rsp.addExtension(srsp);
            }
        }
    }
}