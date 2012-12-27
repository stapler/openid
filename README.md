Server-side implementation of the OpenID protocol
==========================

This library builds on `openid4java` library and implements the server-side protocol.

To use this library, you need to subtype the `Session` class and provides the logic that actually authenticates the user on the server-side (this information is then sent to the OpenID client requesting authentication.)

The `OpenIDServer` class is the object you bind to the URL space. Normally this is a singleton object.
