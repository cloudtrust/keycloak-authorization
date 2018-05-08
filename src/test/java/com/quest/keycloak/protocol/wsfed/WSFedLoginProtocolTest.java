package com.quest.keycloak.protocol.wsfed;

import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.Before;
import org.junit.Test;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

public class WSFedLoginProtocolTest {
    private WSFedLoginProtocol protocol;

    private MockHelper mh = new MockHelper();

    @Before
    public void init() throws IOException {
        mh.initMocks();
        protocol = new WSFedLoginProtocol();
        protocol.setSession(mh.getSession());
        protocol.setRealm(mh.getRealm());
        protocol.setUriInfo(mh.getUriInfo());
    }

    @Test
    public void testAuthenticatedNotAuthorized(){
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedAuthorized(){
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }
}
