# Keycloak authorization module

The purpose of this module is to add authorization capabilities to keycloak for a given client, whether the client 
itself has the capability to handle authorization or not. This means that:

* Any type of keycloak client can have an authorization layered on top of authentication, not just OIDC clients.
* The authorization only works as long as keycloak is in the path of requests to a resource.