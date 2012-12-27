package org.kohsuke.stapler.openid.client;

import org.kohsuke.stapler.AttributeKey;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.sreg.SRegRequest;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;

/**
 * Captures the in-progress OpenID authentication session and its result.
 *
 * @author Kohsuke Kawaguchi
 */
public class OpenIdSession implements Serializable  {
    // fake serializable just to make Tomcat happy
    private transient final ConsumerManager manager;
    private transient final DiscoveryInformation endpoint;
    private transient String from;
    private transient final String finishUrl;

    /**
     * Authenticated identity.
     */
    private OpenIDIdentity identity;

    /**
     * @param openid
     *      The identity that the user has claimed, which we are going to validate.
     * @param thisUrl
     *      URL that this {@link OpenIdSession} object is mapped to. Used to construct
     *      the URL to bring the user back to.
     */
    public OpenIdSession(ConsumerManager manager, String openid, String thisUrl) throws OpenIDException, IOException {
        this.manager = manager;

        List discoveries = manager.discover(openid);
        endpoint = manager.associate(discoveries);
        finishUrl = thisUrl+"/finishLogin";
    }

    /**
     * If the user is already authenticated, return the identity information.
     * Otherwise start an authentication session (by throwing {@link HttpResponse}.)
     */
    public OpenIDIdentity authenticate() {
        if (identity==null)
            commence();     // this redirects the user and will never return
        return identity;
    }

    /**
     * Starts the login session.
     */
    public void commence() {
        try {
            this.from = Stapler.getCurrentRequest().getRequestURIWithQueryString();
            final AuthRequest authReq = manager.authenticate(endpoint, finishUrl);

            SRegRequest sregReq = SRegRequest.createFetchRequest();
            sregReq.addAttribute("fullname", false);
            sregReq.addAttribute("nickname", true);
            sregReq.addAttribute("email", false);
            authReq.addExtension(sregReq);

            String url = authReq.getDestinationUrl(true);

            // remember this in the session
            KEY.set(this);

            throw new HttpRedirect(url);
        } catch (OpenIDException e) {
            throw HttpResponses.error(e);
        }
    }

    /**
     * When the identity provider is done with its thing, the user comes back here.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException, OpenIDException {
        // extract the parameters from the authentication process
        // (which comes in as a HTTP extend from the OpenID provider)
        ParameterList responselist = new ParameterList(request.getParameterMap());

        // verify the process
        VerificationResult verification = manager.verify(request.getRequestURLWithQueryString().toString(), responselist, endpoint);

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();
        if (verified == null)
            throw HttpResponses.error(500,"Failed to login: " + verification.getStatusMsg());

        this.identity = new OpenIDIdentity((AuthSuccess) verification.getAuthResponse());

        return HttpResponses.redirectTo(from);
    }

    public static final AttributeKey<OpenIdSession> KEY = AttributeKey.sessionScoped();

    private static final long serialVersionUID = 1L;
}
