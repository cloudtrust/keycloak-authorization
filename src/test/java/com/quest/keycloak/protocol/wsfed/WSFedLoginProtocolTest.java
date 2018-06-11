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

    private MockHelper mh;

    @Before
    public void init() throws IOException {
        mh = new MockHelper();
        mh.initMocks();
        protocol = new WSFedLoginProtocol();
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
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupNotAuthorized(){
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        mh.setPolicy(mh.getGroupPolicy());
        mh.enableWsfedGroupMapper();
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupAuthorized(){
        mh.setPolicy(mh.getGroupPolicy());
        mh.setGroup();
        mh.enableWsfedGroupMapper();
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupSingleMemberAuthorized(){
        mh.setPolicy(mh.getGroupPolicy());
        mh.setGroupSingleMember();
        mh.enableWsfedGroupMapper();
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedGroupAuthorizedSAML11(){
        mh.setPolicy(mh.getGroupPolicy());
        mh.setGroup();
        mh.enableWsfedGroupMapper();
        when(mh.getClient().getAttribute(WSFedLoginProtocol.WSFED_SAML_ASSERTION_TOKEN_FORMAT))
                .thenReturn(WsFedSAMLAssertionTokenFormat.SAML11_ASSERTION_TOKEN_FORMAT.get());
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getUserSession(),mh.getClientSession());
        assertNotNull(r);
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }

}
