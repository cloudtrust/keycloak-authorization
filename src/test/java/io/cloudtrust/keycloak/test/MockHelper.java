package io.cloudtrust.keycloak.test;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.policy.provider.user.UserPolicyProviderFactory;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.util.JsonSerialization;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * The purpose of this class is to create the MOCKS that are necessary to run keycloak code. The main reason for this is
 * that keycloak takes a lot of the information that it uses from two sources:
 * 1) The database. The actual classes holding the data for this live in org.keycloak.models.jpa and rely on
 *    Hibernate/EntityManager to sync with the DB
 * 2) The cache, which is managed by infinispan. The actual classes that hold the data reside in
 *    org.keycloak.models.cache.infinispan.
 *
 * In the keycloak code only interface Models are referenced, for example a User is described by a UserModel interface
 * and a Realm or Client are referenced by the RealmModel and ClientModel interfaces. In practice, there would be
 * UserAdapter, RealmAdapter and ClientAdapter objects (the classes that extend those interfaces) when the code is
 * is running.
 *
 * While the objects that are represented in the database can be represented by either database or cache objects, there
 * are also some objects that are only held in the cache. This would be information that would pertain to the running
 * sessions and their state. Once again, the pattern is the same: there is an interface representing the state, and a
 * class which contains the actual information from the cache. An example for this would be the UserSessionModel
 * and the UserSessionAdapter for UserSessions. In this case however, there is only the cache object, not the jpa object.
 *
 * It is OK and necessary to create Mocks for all the objects that would come from the database or hold state, as
 * neither would be available when unit testing (and note that in some situations mocks for state shouldn't be created,
 * but replaced by actual objects). However, think long and hard before mocking any other behaviour or logic.
 */
public class MockHelper {

    //Mocks for DB elements
    @Mock
    private ClientModel client;
    @Mock
    private RealmModel realm;
    @Mock
    private UserModel user;
    @Mock
    private RoleModel role;

    //Mocks for DB elements attached to authorization elements
    @Mock
    private ResourceStore resourceStore;
    @Mock
    private StoreFactory storeFactory;
    @Mock
    private ResourceServer resourceServer;
    @Mock
    private ResourceServerStore resourceServerStore;
    @Mock
    private Resource resource;
    @Mock
    private PolicyStore policyStore;
    @Mock
    private Policy parentPolicy;
    @Mock
    private Policy userPolicy;

    //Mocks for sessions
    @Mock
    private KeycloakSession session;
    @Mock
    private UserSessionModel userSession;
    @Mock
    private AuthenticatedClientSessionModel clientSession;

    //Other mocks
    @Mock
    private UriInfo uriInfo;
    @Mock
    private KeyManager keyManager;

    /**
     * Initialises the mocks, must be called at least once in the test classes using this class. Can also be called
     * to reset the state of modified mocks.
     * @throws IOException
     */
    public void initMocks() throws IOException {
        MockitoAnnotations.initMocks(this);
        initRealm();
        initClient();
        initUser();
        initRole();

        initStoreFactory();
        initResourceServerStore();
        initResourceServer();
        initResourceStore();
        initResource();
        initPolicyStore();
        initPolicy();

        initUserSession();
        initClientSession();
        initSession();

        initUriInfo();
        initKeyManager();
    }

    /**
     * Initialises a keycloak realm called "testRealm"
     */
    private void initRealm() {
        when(realm.getName()).thenReturn("testRealm");
        when(realm.isEnabled()).thenReturn(true);
        when(realm.getSslRequired()).thenReturn(SslRequired.ALL);
        when(realm.getAccessCodeLifespan()).thenReturn(1000);
        when(realm.getAccessTokenLifespan()).thenReturn(2000);
        when(realm.getRoleById(role.getId())).thenReturn(role);
    }

    public RealmModel getRealm() {
        return realm;
    }

    /**
     * Initialises a keycloak client of unspecified protocol
     */
    private void initClient() {
        when(client.getId()).thenReturn(UUID.randomUUID().toString()) ;
        when(client.getClientId()).thenReturn(getClientId());
        when(client.isEnabled()).thenReturn(true);
    }
    private String getClientId(){return "urn:test:example";}

    public ClientModel getClient() {
        return client;
    }

    /**
     * Initialises a test user
     */
    private void initUser() {
        when(user.getId()).thenReturn(getUserId());
        when(user.getUsername()).thenReturn("testUser");
        when(user.getEmail()).thenReturn("testUser@test.com");
    }
    private String getUserId(){
        return "e43169e4-82ac-4f7b-a8e3-9806d34c2825";
    }

    public UserModel getUser() {
        return user;
    }

    /**
     * Initialises a "user" role
     */
    private void initRole() {
        when(role.getId()).thenReturn(UUID.randomUUID().toString());
        when(role.getName()).thenReturn("user");
        when(role.getContainer()).thenReturn(realm);
    }

    /**
     * Initialises the StoreFactory.
     * The StoreFactory is a base element that allows the retrieval of the other "stores" that hold authorization
     * elements. A store is the group of all elements of a certain type: for example, the collection of all Policies
     * is the PolicyStore
     */
    private void initStoreFactory() {
        when(storeFactory.getResourceStore()).thenReturn(resourceStore);
        when(storeFactory.getResourceServerStore()).thenReturn(resourceServerStore);
        when(storeFactory.getPolicyStore()).thenReturn(policyStore);
    }

    /**
     * Initialises the ResourceServerStore. A ResourceServer is a client which has had the authorization enabled.
     */
    private void initResourceServerStore(){
        when(resourceServerStore.findById(client.getId())).thenReturn(resourceServer);
    }

    public ResourceServerStore getResourceServerStore() {
        return resourceServerStore;
    }

    /**
     * Initialises a ResourceServer.  A ResourceServer is a client which has had the authorization enabled.
     */
    private void initResourceServer(){
        when(resourceServer.getId()).thenReturn(getClientId());
        when(resourceServer.getPolicyEnforcementMode()).thenReturn(PolicyEnforcementMode.ENFORCING);
    }

    /**
     * Initialises a ResourceStore. A resource is an element of a website to be protected by authorization.
     */
    private void initResourceStore() {
        when(resourceStore.findByOwner(resourceServer.getId(), resourceServer.getId())).thenReturn(Collections.singletonList(resource));
    }

    /**
     * Initialises a Resource of type Default resource. In non-mock life, the Default resource is the resource
     * automatically created when a client is made into a resource server (i.e. authorization is added)
     */
    private void initResource(){
        when(resource.getId()).thenReturn(UUID.randomUUID().toString());
        when(resource.getName()).thenReturn("Default Resource");
        when(resource.getOwner()).thenReturn(getClientId());
        when(resource.getUri()).thenReturn("/*");
        when(resource.getScopes()).thenReturn(Collections.emptyList());
        when(resource.getType()).thenReturn("urn:" + getClientId() + ":default");
        when(resource.getResourceServer()).thenReturn(resourceServer);
    }

    /**
     * Initialises a PolicyStore
     */
    private void initPolicyStore(){
        when(policyStore.findByResource(resource.getId(), resourceServer.getId())).thenReturn(Collections.singletonList(parentPolicy));
        when(policyStore.findByResourceType(resource.getType(), resourceServer.getId())).thenReturn(Collections.singletonList(parentPolicy));
    }

    /**
     * Initialises the Policies. Note that what in keycloak are "Policies" and "Permissions" in the keycloak GUI are the
     * same thing behind the scenes in the code. So here we initialise the "permission" (parent policy) and the
     * actual "policy" (user policy)
     * @throws IOException raised if there's a problem with the JsonSerialisation of the userId
     */
    private void initPolicy() throws IOException {
        when(parentPolicy.getAssociatedPolicies()).thenReturn(Collections.singleton(userPolicy));
        when(parentPolicy.getDecisionStrategy()).thenReturn(DecisionStrategy.UNANIMOUS);
        when(userPolicy.getType()).thenReturn("user");
        when(userPolicy.getLogic()).thenReturn(Logic.NEGATIVE);
        when(userPolicy.getConfig()).thenReturn(Collections.singletonMap("users", JsonSerialization.writeValueAsString(Collections.singleton(getUserId()))));
    }

    public Policy getUserPolicy() {
        return userPolicy;
    }

    private void initSession(){
        when(session.getProvider(StoreFactory.class)).thenReturn(storeFactory);
        KeycloakContext context = Mockito.mock(KeycloakContext.class);
        when (session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        LoginFormsProvider loginFormsProvider = Mockito.mock(LoginFormsProvider.class);
        when(loginFormsProvider.setAuthenticationSession(any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString(), any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.createErrorPage(any(Response.Status.class))).thenAnswer((Answer<Response>) invocation -> Response.status((Response.Status) invocation.getArguments()[0]).build());
        when (session.getProvider(LoginFormsProvider.class)).thenReturn(loginFormsProvider);
        when(session.keys()).thenReturn(keyManager);

        Map<String, PolicyProviderFactory> polFactoMap = new HashMap<>();
        polFactoMap.put("user", new UserPolicyProviderFactory());
        AuthorizationProvider authorizationProvider = new AuthorizationProvider(session, realm, polFactoMap);
        when(session.getProvider(AuthorizationProvider.class)).thenReturn(authorizationProvider);
    }

    public KeycloakSession getSession() {
        return session;
    }

    private void initUserSession() {
        when(userSession.getId()).thenReturn(UUID.randomUUID().toString());
        when(userSession.getBrokerSessionId()).thenReturn(UUID.randomUUID().toString());
        when(userSession.getUser()).thenReturn(user);
        Map<String, AuthenticatedClientSessionModel> map = Collections.singletonMap(client.getId(), clientSession);
        when(userSession.getAuthenticatedClientSessions()).thenReturn(map);
        doReturn(user.getId()).when(userSession).getBrokerUserId();
        when(userSession.isOffline()).thenReturn(true);
    }

    public UserSessionModel getUserSession() {
        return userSession;
    }

    private void initClientSession() {
        when(clientSession.getId()).thenReturn(UUID.randomUUID().toString());
        when(clientSession.getClient()).thenReturn(client);
        when(clientSession.getRedirectUri()).thenReturn(getClientId());
        when(clientSession.getNote("SSO_AUTH")).thenReturn("true");
        String roleId = role.getId();
        when(clientSession.getRoles()).thenReturn(Collections.singleton(roleId));
        when(clientSession.getUserSession()).thenReturn(userSession);
        when(clientSession.getRealm()).thenReturn(realm);
    }

    public AuthenticatedClientSessionModel getClientSession() {
        return clientSession;
    }


    private void initUriInfo() {
        //We have to use thenAnswer so that the UriBuilder gets created on each call vs at mock time.
        when(uriInfo.getBaseUriBuilder()).
                thenAnswer(new Answer<UriBuilder>() {
                    public UriBuilder answer(InvocationOnMock invocation) {
                        return UriBuilder.fromUri("https://cloudtrust.io/auth");
                    }
                });

        URI baseUri = uriInfo.getBaseUriBuilder().build();
        when(uriInfo.getBaseUri()).thenReturn(baseUri);
    }

    public UriInfo getUriInfo() {
        return uriInfo;
    }

    /**
     * Initialises a keymanager with actual keys (sort of). Using a DefaultKeyManager is complicated due to the requirements on
     * the KeycloakSession (providers, factories), so a mock is used instead
     */
    private void initKeyManager() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509Certificate certificate = null;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        SecretKey secret = new SecretKeySpec("junit".getBytes(), "HmacSHA256");
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("This shouldn't happen");
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(Arrays.copyOf(sha.digest(("junit").getBytes()), 16), "AES");
        KeyManager.ActiveHmacKey activeHmacKey = new KeyManager.ActiveHmacKey(UUID.randomUUID().toString(), secret);
        KeyManager.ActiveRsaKey activeRsaKey = new KeyManager.ActiveRsaKey(UUID.randomUUID().toString(), keyPair.getPrivate(), keyPair.getPublic(), certificate);
        KeyManager.ActiveAesKey activeAesKey = new KeyManager.ActiveAesKey(UUID.randomUUID().toString(), secretKeySpec);
        when(keyManager.getActiveHmacKey(realm)).thenReturn(activeHmacKey);
        when(keyManager.getActiveRsaKey(realm)).thenReturn(activeRsaKey);
        when(keyManager.getActiveAesKey(realm)).thenReturn(activeAesKey);
    }
}
