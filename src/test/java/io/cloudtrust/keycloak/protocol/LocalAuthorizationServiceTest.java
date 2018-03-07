package io.cloudtrust.keycloak.protocol;

import com.example.mockito.MockitoExtension;
import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.*;
import org.keycloak.services.managers.ClientSessionCode;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.*;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class LocalAuthorizationServiceTest {

    private ClientSessionCode<AuthenticatedClientSessionModel> accessCode;
    private MockHelper mh = new MockHelper();

    @BeforeEach
    public void beforeEach() throws IOException {
        mh.initMocks();
        accessCode = new ClientSessionCode<>(mh.getSession(), mh.getRealm(), mh.getClientSession());
    }

    @Test
    public void testIsAuthorizedNoResourceServer() {
        when(mh.getResourceServerStore().findById(any())).thenReturn(null);
        LocalAuthorizationService las = new LocalAuthorizationService(mh.getSession(), mh.getRealm());
        Response r = las.isAuthorized(mh.getClient(), mh.getUserSession(), mh.getClientSession(), accessCode);
        assertNull(r);
    }

    @Test
    public void testIsAuthorizedUserNotOk() {
        LocalAuthorizationService las = new LocalAuthorizationService(mh.getSession(), mh.getRealm());
        Response r = las.isAuthorized(mh.getClient(), mh.getUserSession(), mh.getClientSession(), accessCode);
        assertNotNull(r);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), r.getStatus());
    }

    @Test
    public void testIsAuthorizeUserOk(){
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        LocalAuthorizationService las = new LocalAuthorizationService(mh.getSession(), mh.getRealm());
        Response r = las.isAuthorized(mh.getClient(), mh.getUserSession(), mh.getClientSession(), accessCode);
        assertNull(r);
    }

    @Test
    public void testIsAuthorizedErrorProcessingPolicies(){
        when(mh.getUserPolicy().getType()).thenReturn("js");
        LocalAuthorizationService las = new LocalAuthorizationService(mh.getSession(), mh.getRealm());
        Response r = las.isAuthorized(mh.getClient(), mh.getUserSession(), mh.getClientSession(), accessCode);
        assertNotNull(r);
        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), r.getStatus());
    }
}
