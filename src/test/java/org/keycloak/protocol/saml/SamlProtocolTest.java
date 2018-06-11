package org.keycloak.protocol.saml;

import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.Before;
import org.junit.Test;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SamlProtocolTest {

    private SamlProtocol protocol;
    private MockHelper mh = new MockHelper();

    @Before
    public void init() throws IOException {
        mh.initMocks();
        protocol = new SamlProtocol();
        protocol.setSession(mh.getSession());
        protocol.setRealm(mh.getRealm());
        protocol.setUriInfo(mh.getUriInfo());
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
        assertEquals(Response.Status.FOUND.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupNotAuthorized(){
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        mh.setPolicy(mh.getGroupPolicy());
        mh.enableSamlGroupMapper();
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupAuthorized(){
        mh.setPolicy(mh.getGroupPolicy());
        mh.enableSamlGroupMapper();
        mh.setGroup();
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.FOUND.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupSingleMemberAuthorized(){
        mh.setPolicy(mh.getGroupPolicy());
        mh.enableSamlGroupMapper();
        mh.setGroupSingleMember();
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.FOUND.getStatusCode(), r.getStatus());
    }
}
