package io.cloudtrust.protocol;

import org.jboss.logging.Logger;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.KeycloakEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.authorization.util.Permissions;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;

import javax.ws.rs.core.Response;
import java.util.List;

public final class LocalAuthorizationService {

    private static final Logger logger = Logger.getLogger(LocalAuthorizationService.class);

    private final KeycloakSession session;
    private final RealmModel realm;

    public LocalAuthorizationService(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    public Response isAuthorized(ClientModel client, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession, ClientSessionCode<AuthenticatedClientSessionModel> accessCode) {
        AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
        StoreFactory storeFactory = authorization.getStoreFactory();
        UserModel user = userSession.getUser();
        ResourceServer resourceServer = storeFactory.getResourceServerStore().findById(client.getId());
        if (resourceServer == null) {
            return null; //permissions not enabled
        }
        TokenManager tokenManager = new TokenManager();
        AccessToken accessToken = tokenManager.createClientAccessToken(session, accessCode.getRequestedRoles(), realm, client, user, userSession, clientSession);

        KeycloakIdentity identity = new KeycloakIdentity(accessToken, session, realm);

        List<ResourcePermission> permissions = Permissions.all(resourceServer, identity, authorization);

        try {
            List<Result> result = authorization.evaluators().from(permissions, new KeycloakEvaluationContext(identity, authorization.getKeycloakSession())).evaluate();
            List<Permission> entitlements = Permissions.permits(result, null, authorization, resourceServer);

            if (!entitlements.isEmpty()) {
                return null; //authorization ok
            }
        } catch (Exception cause) {
            logger.error("Failed to evaluate permissions", cause);
            return ErrorPage.error(session, null, Response.Status.INTERNAL_SERVER_ERROR, "Error while evaluating permissions.");
        }

        return ErrorPage.error(session, null, Response.Status.FORBIDDEN, "not_authorized");
    }
}
