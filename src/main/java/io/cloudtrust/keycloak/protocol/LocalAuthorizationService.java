package io.cloudtrust.keycloak.protocol;

import org.jboss.logging.Logger;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.KeycloakEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.authorization.util.Permissions;
import org.keycloak.dom.saml.common.CommonAssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeStatementType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeType;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;

import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The local authorisation service's purpose is to provide keycloak with a method to filter a user's access to a client
 * based on the user itself or the user's attributes.
 * <p>
 * The class's methods uses keycloak's existing authorisation framework to determine if a user is authorised to access
 * a client's resources, and returns an appropriate response if the user has its access denied.
 * <p>
 * The goal is to allow authentication, but disallow access to the client, so the methods of this class should be called
 * in a protocol's {@link org.keycloak.protocol.LoginProtocol#authenticated} method before the actual access response is
 * returned.
 *
 * @author ADD
 */
public final class LocalAuthorizationService {

    private static final Logger logger = Logger.getLogger(LocalAuthorizationService.class);

    private final KeycloakSession session;
    private final RealmModel realm;

    /**
     * Basic constructor
     *
     * @param session The current keycloak session
     * @param realm   The current keycloak realm
     */
    public LocalAuthorizationService(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    /**
     * This method evaluates whether or not a user is authorised to access a client based on the authorisation values
     * set in the client. If the user is not authorised, the method returns a 403 FORBIDDEN error page. If the user
     * is authorised, the method returns null. Having no authorisation set for a client is equivalent to being authorised.
     *
     * @param client The client to which access is currently being requested
     * @param userSession The session of the user which is asking for access to the client's resources
     * @param clientSession The client session currently being used
     * @param accessCode The client session code TODO figure out what this actually is
     * @param samlAssertion A SAML assertion. This should only be given for protocols that use SAML tokens. For the others, it should be set to null
     * @return {@code true} if the user is not authorised to access the client, false otherwise
     */
    public boolean isAuthorized(ClientModel client, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession,
                                ClientSessionCode<AuthenticatedClientSessionModel> accessCode, CommonAssertionType samlAssertion) {
        AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
        StoreFactory storeFactory = authorization.getStoreFactory();
        UserModel user = userSession.getUser();
        ResourceServer resourceServer = storeFactory.getResourceServerStore().findById(client.getId());
        if (resourceServer == null) {
            return true; //permissions not enabled
        }
        TokenManager tokenManager = new TokenManager();
        AccessToken accessToken = tokenManager.createClientAccessToken(session, accessCode.getRequestedRoles(), realm, client, user, userSession, clientSession);
        accessToken.getOtherClaims().putAll(getClaims(samlAssertion));
        KeycloakIdentity identity = new KeycloakIdentity(accessToken, session, realm);

        Resource resource=storeFactory.getResourceStore().findByName("Keycloak Client Resource", resourceServer.getId());
        List<ResourcePermission> permissions = Collections.singletonList(new ResourcePermission(resource, new ArrayList<>(), resourceServer));

        List<Result> result = authorization.evaluators().from(permissions, new KeycloakEvaluationContext(identity, authorization.getKeycloakSession())).evaluate();
        List<Permission> entitlements = Permissions.permits(result, null, authorization, resourceServer);

        return !entitlements.isEmpty();
    }

    /**
     * This method takes a SAML 1.1 or SAML 2.0 assertion, and extracts the attributes (claims), returning the
     * values in a
     * @param samlAssertion
     * @return
     */
    private Map<String, List<Object>> getClaims(CommonAssertionType samlAssertion){
        Map<String,List<Object>> result = new HashMap<>();
        if (samlAssertion instanceof SAML11AssertionType) {
            SAML11AssertionType assertionType = (SAML11AssertionType) samlAssertion;
            List<SAML11AttributeType> attributes = assertionType.getStatements().stream()
                    .filter(x -> x instanceof SAML11AttributeStatementType)
                    .map(SAML11AttributeStatementType.class::cast)
                    .flatMap(x -> x.get().stream())
                    .collect(Collectors.toList());
            for (SAML11AttributeType attribute: attributes) {
                if (!result.containsKey(attribute.getAttributeName())){
                    result.put(attribute.getAttributeName(), new ArrayList<>());
                }
                result.get(attribute.getAttributeName()).addAll(attribute.get());
            }
        } else if (samlAssertion instanceof AssertionType) {
            AssertionType assertionType = (AssertionType) samlAssertion;
            List<AttributeType> attributes = assertionType.getAttributeStatements().stream()
                    .flatMap(x -> x.getAttributes().stream())
                    .map(AttributeStatementType.ASTChoiceType::getAttribute)
                    .collect(Collectors.toList());
            for (AttributeType attribute: attributes) {
                if (!result.containsKey(attribute.getName())){
                    result.put(attribute.getName(), new ArrayList<>());
                }
                result.get(attribute.getName()).addAll(attribute.getAttributeValue());
            }
        }

        return result;
    }

    /**
     * This method evaluates whether or not a user is authorised to access a client based on the authorisation values
     * set in the client. If the user is not authorised, the method returns a 403 FORBIDDEN error page. If the user
     * is authorised, the method returns null. Having no authorisation set for a client is equivalent to being authorised.
     *
     * @param client The client to which access is currently being requested
     * @param userSession The session of the user which is asking for access to the client's resources
     * @param clientSession The client session currently being used
     * @param accessCode The client session code TODO figure out what this actually is
     * @param samlAssertion A SAML assertion. This should only be given for protocols that use SAML tokens. For the others, it should be set to null
     * @return A 403 FORBIDDEN error page if the user is not authorised to access the client, and null otherwise
     */
    public Response isAuthorizedResponse(ClientModel client, UserSessionModel userSession,
                                         AuthenticatedClientSessionModel clientSession,
                                         ClientSessionCode<AuthenticatedClientSessionModel> accessCode,
                                         CommonAssertionType samlAssertion) {
        try {
            boolean authorized=isAuthorized(client, userSession, clientSession, accessCode, samlAssertion);
            if(authorized){
                return null;
            }else{
                return ErrorPage.error(session, null, Response.Status.FORBIDDEN, "not_authorized");
            }
        } catch (Exception cause) {
            logger.error("Failed to evaluate permissions", cause);
            return ErrorPage.error(session, null, Response.Status.INTERNAL_SERVER_ERROR, "Error while evaluating permissions.");
        }
    }
}
