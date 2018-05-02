package org.keycloak.protocol.oidc;

import io.cloudtrust.keycloak.protocol.LocalAuthorizationService;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.oidc.endpoints.TokenEndpoint;
import org.keycloak.representations.idm.*;
import org.keycloak.representations.idm.authorization.*;
import org.keycloak.test.TestsHelper;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;

//TODO put back arquillian when classloader order is fixed
//@RunWith(Arquillian.class)
//@RunAsClient
public class OIDCLoginProtocolTest {

    protected static final Logger logger = Logger.getLogger(OIDCLoginProtocolTest.class);

    private static final String MODULE_JAR = "keycloak-authorization";
    private static final String CLIENT = "authorization";
    private static final String SECRET = "**********";
    private static final String TEST_REALM_NAME = "test-authorization";

    @BeforeClass
    public static void initRealmAndUsers() throws IOException {
        TestsHelper.baseUrl=TestsHelper.keycloakBaseUrl;
        TestsHelper.importTestRealm("admin", "admin", "/"+TEST_REALM_NAME+"-realm.json");
    }

    @AfterClass
    public static void resetRealm() {
        try {
            TestsHelper.deleteRealm("admin", "admin", TEST_REALM_NAME);
        } catch (IOException e) {
            logger.error("delete realm failed, catching excpetion to allow arquillian to undeploy correctly");
            e.printStackTrace();
        }
    }

//    @Deployment(name=MODULE_JAR, testable = false)
//    @TargetsContainer("keycloak-remote")
//    public static Archive<?> createProviderArchive() throws IOException {
//        JavaArchive archive = ShrinkWrap.create(JavaArchive.class, "keycloak-authorization.jar")
//                .addClasses(
//                        TokenEndpoint.class,
//                        OIDCLoginProtocolService.class,
//                        LocalAuthorizationService.class,
//                        OIDCLoginProtocol.class,
//                        OIDCLoginProtocolFactory.class
//                )
//                .addAsManifestResource(new File("src/test/resources", "MANIFEST.MF"))
//                .addAsServiceProvider(LoginProtocolFactory.class, OIDCLoginProtocolFactory.class);
//        return archive;
//    }

    @Test
    public void user1CantLoginUsingTokenEndpointAccessToken() throws IOException {
        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user1", "password", CLIENT, SECRET);
        String token=keycloak.tokenManager().getAccessTokenString();
        Assert.assertNotNull(token);
    }

    @Test(expected = ForbiddenException.class)
    public void user2CantLoginUsingTokenEndpointAccessToken() throws IOException {
        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user2", "password", CLIENT, SECRET);
        keycloak.tokenManager().getAccessTokenString();
    }

    @Test
    public void user1CantLoginUsingTokenEndpointRefreshToken() throws IOException {
        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user1", "password", CLIENT, SECRET);
        keycloak.tokenManager().getAccessToken();
        String token=keycloak.tokenManager().refreshToken().getToken();
        Assert.assertNotNull(token);
    }

    @Test(expected = ForbiddenException.class)
    public void user2CantLoginUsingTokenEndpointRefreshToken() throws IOException {
        Keycloak keycloakAdmin = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, "master", "admin", "admin", "admin-cli", null);
        ClientRepresentation client = keycloakAdmin.realm(TEST_REALM_NAME).clients().findByClientId(CLIENT).get(0);
        ResourceServerRepresentation resourceServer = keycloakAdmin.realm(TEST_REALM_NAME).clients().get(client.getId()).authorization().getSettings();
        resourceServer.setPolicyEnforcementMode(PolicyEnforcementMode.DISABLED);
        keycloakAdmin.realm(TEST_REALM_NAME).clients().get(client.getId()).authorization().update(resourceServer);
        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user2", "password", CLIENT, SECRET);
        keycloak.tokenManager().getAccessToken();
        resourceServer.setPolicyEnforcementMode(PolicyEnforcementMode.ENFORCING);
        keycloakAdmin.realm(TEST_REALM_NAME).clients().get(client.getId()).authorization().update(resourceServer);
        keycloak.tokenManager().refreshToken().getToken();
    }

//    @Test
//    public void user1CantLoginUsingTokenEndpointAuthorizationCode() throws IOException {
//        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user1", "password", CLIENT, SECRET);
//        String token=keycloak.
//        Assert.assertNotNull(token);
//    }
//
//    @Test(expected = ForbiddenException.class)
//    public void user2CantLoginUsingTokenEndpointAuthorizationCode() throws IOException {
//        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user2", "password", CLIENT, SECRET);
//        keycloak.tokenManager().getAccessTokenString();
//    }
}
