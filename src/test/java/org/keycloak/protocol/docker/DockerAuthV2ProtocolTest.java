package org.keycloak.protocol.docker;

import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class DockerAuthV2ProtocolTest {

    private MockHelper mh = new MockHelper();

    DockerAuthV2Protocol protocol;

    @Before
    public void init() throws IOException {
        mh.initMocks();
        protocol = new DockerAuthV2Protocol();
        protocol.setSession(mh.getSession());
        protocol.setRealm(mh.getRealm());
        protocol.setUriInfo(mh.getUriInfo());
        protocol.setEventBuilder((new EventBuilder(mh.getRealm(), mh.getSession(), new ClientConnection() {
            @Override
            public String getRemoteAddr() {
                return "127.0.0.1";
            }

            @Override
            public String getRemoteHost() {
                return "localhost";
            }

            @Override
            public int getRemotePort() {
                return 0;
            }

            @Override
            public String getLocalAddr() {
                return null;
            }

            @Override
            public int getLocalPort() {
                return 0;
            }
        })).event(EventType.LOGIN));
    }

    @Test
    public void testAuthenticatedNotAuthorized(){
        mh.setPolicy(mh.getUserPolicy());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedAuthorized(){
        mh.setPolicy(mh.getUserPolicy());
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }
}
