package org.kohsuke.stapler.openid.server;

/**
 * Represents the information of the current user as seen by this server.
 *
 * <p>
 * This is populated by the user of this library, and the information gets passed
 * to the OpenID client.
 *
 * @author Kohsuke Kawaguchi
 */
public class OpenIDIdentity {
    private String nick,email,fullName,lastName,firstName;

    public OpenIDIdentity withNick(String nick) {
        this.nick = nick;
        return this;
    }

    public OpenIDIdentity withEmail(String email) {
        this.email = email;
        return this;
    }

    public OpenIDIdentity withFullName(String fullName) {
        this.fullName = fullName;
        return this;
    }

    public OpenIDIdentity withLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public OpenIDIdentity withFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public String getNick() {
        return nick;
    }

    public void setNick(String nick) {
        this.nick = nick;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getOpenId(OpenIDServer server) {
        if (nick==null)     throw new IllegalStateException("nick field is not set");
        return server.address+"~"+nick;
    }
}
