# Keycloak authorization module

The purpose of this module is to add authorization capabilities to keycloak for a given client, whether the client 
itself has the capability to handle authorization or not. This means that:

* Any type of keycloak client can have an authorization layered on top of authentication, not just OIDC clients.
* The authorization only works as long as keycloak is in the path of requests to a resource.

While best practice is to have the client handle authorisation tasks, if necessary with the aid of an external service, 
many clients do not have this capability. This is why IDPs such as Microsoft's Azure AD offer this service, and why we
provide this module for keycloak.

It should be noted that the authorization step happens after authentication, so a user which is connected in SSO will
not need re-input his login details to when switching between clients he has access to, and clients which he doesn't
have access to.

## How to install

## How to use

## How this module works

This module is unfortunately very strongly linked to keycloak's code. This is due to the fact that we are rewriting the 
behaviour of keyclock's protocol classes without actually modifying the keycloak code. The way this works is as follows:

1) We declare in the LoginProtocolFactory services' file that we are declaring the factories for keycloak's protocols.
As we have the base class as a dependency, this means that our module's declaration comes after keycloak's own. Since
Keycloak uses a map to store this information, we overwrite the dependency
1) We use a local copy the relevant keycloak classes that we need to work with for each protocol:
    * **The login protocol factory** This ensures that when the factory is created, it will call local code first, due to
    wildfly's classloader priority order (local classes are called before dependency classes). In this case, it includes
    the creation of the endpoint.
    * **The endpoint/service** We take this class to ensure that when the http request is called, it is our endpoint that 
    is called. This will ensure that the local LoginProtocol is called.
    * **The login protocol** This is only class we actually modify. In the authenticated method we invoke the code to 
    verify that the client is authorised to access the client it wishes to connect to.
1) We use a theme to add to the administrator pages the option to enable authorisation for all clients.

We call keycloak's own existing authorisation methods and framework for a user's authorisation. This is done in the  
methods of the class io.cloudtrust.keycloak.protocol.LocalAuthorizationService. 

## How to update the code when keycloak changes version number

When keycloak changes version number, we must replace all classes (login protocol factory, endpoint/service, login 
protocol) of the module with their new version from keycloak and the corresponding keycloak WS-FED module. A call to
the LocalAuthorisationService's methods must be then added in the login protocol's `authenticated` method

The LocalAuthorisationService must only be updated if the functions called change signature. The same is true for the
tests. For these steps it necessary to understand how the keycloak classes and authorization functions work.

## Removing the dependency on WS-FED

This module is designed to work with our WS-FED protocol module. However, to remove this dependency simply:
1) Remove the package `com.quest.keycloak.protocol.wsfed` in the main and test directories
1) Remove the dependency to `keycloak-wsfed` in the `pom.xml`
1) Remove the line `<module name="com.quest.keycloak-wsfed"/>` in the module.xml
1) Build the module and deploy it as you would otherwise.