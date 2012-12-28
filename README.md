Stapler/OpenID integration
==========================

This library builds on `openid4java` library and implements the server-side and client-side OpenID protocols.

Server-side
-----------
To use this library, you need to subtype the `Session` class and provides the logic that actually authenticates the user on the server-side (this information is then sent to the OpenID client requesting authentication.)

The `OpenIDServer` class is the object you bind to the URL space. Normally this is a singleton object.

Client-side
-----------
To use the client side of this library, you instanciate `OpenIDSession` class per session and binds it somewhere in the URL space. You call this object's `authenticate()` method and obtain the `OpenIDIdentity` which represents the authenticated user.

If you call this method when the current user is not authenticated, an `HttpResponse` object is thrown to redirect the user to OpenID server for authentication, so the HTTP request that calls into the `authenticate` method better be side-effect free.
