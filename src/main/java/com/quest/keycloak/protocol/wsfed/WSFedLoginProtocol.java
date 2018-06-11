/*
 * Copyright (C) 2015 Dell, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.quest.keycloak.protocol.wsfed;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.common.wsfed.builders.WSFedResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.RequestSecurityTokenResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WSFedOIDCAccessTokenBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WSFedSAML2AssertionTypeBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WsFedSAML11AssertionTypeBuilder;
import io.cloudtrust.keycloak.protocol.LocalAuthorizationService;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.dom.saml.common.CommonAssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.xml.datatype.DatatypeConfigurationException;
import java.io.InputStream;
import java.security.KeyPair;

/**
 * Implementation of keycloak's LoginProtocol. The LoginProtocol is used during the authentication steps for login AND
 * logout - for normal messages and error messages. In our case it called by the AuthorizationEndpoint and
 * Authorisation manager. This class basically handles the protocol components - on a network message level - in the
 * login an logout flows --> the authorisation mechanisms as such are handled by keycloak, but the protocol interface
 * is handled by this class.
 *
 * Created on 5/19/15.
 * @author dbarentine
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 */
public class WSFedLoginProtocol implements LoginProtocol {
    protected static final Logger logger = Logger.getLogger(WSFedLoginProtocol.class);
    public static final String LOGIN_PROTOCOL = "wsfed";

    public static final String WSFED_JWT = "wsfed.jwt";
    public static final String WSFED_X5T = "wsfed.x5t";
    public static final String WSFED_SAML_ASSERTION_TOKEN_FORMAT = "wsfed.saml_assertion_token_format";
    public static final String WSFED_LOGOUT_BINDING_URI = "WSFED_LOGOUT_BINDING_URI";
    public static final String WSFED_CONTEXT = "WSFED_CONTEXT";

    private KeycloakSession session;

    private RealmModel realm;

    protected UriInfo uriInfo;

    protected HttpHeaders headers;

    private EventBuilder event;

    /**
     * Sets the current KeycloakSession
     * @param session the session used for the current connection
     * @return this LoginProtcol (builder pattern)
     */
    @Override
    public LoginProtocol setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    /**
     * Sets the realm currently being used for the login-logout
     * @param realm
     * @return this LoginProtocol (builder pattern)
     */
    @Override
    public LoginProtocol setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    /**
     * TODO check which headers are actually used here
     * @param headers
     * @return this LoginProtocol (builder pattern)
     */
    @Override
    public LoginProtocol setHttpHeaders(HttpHeaders headers) {
        this.headers = headers;
        return this;
    }

    /**
     * TODO findout which uriInfo is actually used here
     * @param uriInfo
     * @return this LoginProtocol (builder pattern)
     */
    @Override
    public LoginProtocol setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return this;
    }

    /**
     * Sets the current EventBuilder (unused though)
     * @param event The event builder used for the current connection
     * @return this LoginProtocol (builder pattern)
     */
    @Override
    public LoginProtocol setEventBuilder(EventBuilder event) {
        this.event = event;
        return this;
    }

    /**
     * Returns a standard keycloak error page. The "cancelled by user" returns a wsfed error, all other errors
     * generate a standard error message
     * @param authSession the model of the session between the resource and keycloak
     * @param error The error message to return
     * @return The Response containing the error page
     */
    @Override
    public Response sendError(AuthenticationSessionModel authSession, Error error) {
        //Replaced cancelLogin
        if(error == Error.CANCELLED_BY_USER) {
            return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, WSFedConstants.WSFED_ERROR_NOTSIGNEDIN);
        }

        return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.FAILED_TO_PROCESS_RESPONSE);
    }

    /**
     * This method sets the response to use when sending back the security tokens after a successful login.
     * WS-FED can use any token type, but this method allows for three: OpenID connect (OIDC), SAML1.1 and
     * SAML 2.0.
     *
     * This method is automatically called by keycloak's AuthenticationManager upon a successful login flow
     * TODO check what information the ClientSessionCode actually carries
     * @param userSession the details of the user session (some user details + state)
     * @param clientSession the client session
     * @return
     */
    @Override
    public Response authenticated(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        ClientSessionCode<AuthenticatedClientSessionModel> accessCode = new ClientSessionCode<>(session, realm, clientSession);
        ClientModel client = clientSession.getClient();
        String context = clientSession.getNote(WSFedConstants.WSFED_CONTEXT);
        userSession.setNote(WSFedConstants.WSFED_REALM, client.getClientId());
        try {
            RequestSecurityTokenResponseBuilder builder = new RequestSecurityTokenResponseBuilder();
            KeyManager keyManager = session.keys();
            KeyManager.ActiveRsaKey activeKey = keyManager.getActiveRsaKey(realm);

            builder.setRealm(clientSession.getClient().getClientId())
                    .setAction(WSFedConstants.WSFED_SIGNIN_ACTION)
                    .setDestination(clientSession.getRedirectUri())
                    .setContext(context)
                    .setTokenExpiration(realm.getAccessTokenLifespan())
                    .setRequestIssuer(clientSession.getClient().getClientId())
                    .setSigningKeyPair(new KeyPair(activeKey.getPublicKey(), activeKey.getPrivateKey()))
                    .setSigningCertificate(activeKey.getCertificate())
                    .setSigningKeyPairId(activeKey.getKid());

            //Declared and used for the Authorization block
            CommonAssertionType samlAssertion = null;

            if (useJwt(client)) {
                //JSON webtoken (OIDC) set in client config
                WSFedOIDCAccessTokenBuilder oidcBuilder = new WSFedOIDCAccessTokenBuilder();
                oidcBuilder.setSession(session)
                        .setUserSession(userSession)
                        .setAccessCode(accessCode)
                        .setClient(client)
                        .setClientSession(clientSession)
                        .setRealm(realm)
                        .setX5tIncluded(isX5tIncluded(client));

                String token = oidcBuilder.build();
                builder.setJwt(token);
            } else {
                //if client wants SAML
                WsFedSAMLAssertionTokenFormat tokenFormat = getSamlAssertionTokenFormat(client);
                switch(tokenFormat) {
                    case SAML20_ASSERTION_TOKEN_FORMAT:
                        AssertionType saml20Token = buildSAML20AssertionToken(userSession, accessCode, clientSession);
                        samlAssertion = saml20Token;
                        builder.setSamlToken(saml20Token);
                        break;
                    case SAML11_ASSERTION_TOKEN_FORMAT:
                        SAML11AssertionType saml11Token = buildSAML11AssertionToken(userSession, accessCode, clientSession);
                        samlAssertion = saml11Token;
                        builder.setSaml11Token(saml11Token);
                        break;
                }
            }

            /*Authorization block*/
            LocalAuthorizationService authorize = new LocalAuthorizationService(session, realm);
            Response authResponse = authorize.isAuthorizedResponse(client, userSession, clientSession, accessCode, samlAssertion);
            if (authResponse != null) {
                return authResponse;
            }
            /*End Authorization block*/

            return builder.buildResponse();
        } catch (Exception e) {
            logger.error("failed", e);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.FAILED_TO_PROCESS_RESPONSE);
        }
    }

    private SAML11AssertionType buildSAML11AssertionToken(UserSessionModel userSession, ClientSessionCode accessCode, AuthenticatedClientSessionModel clientSession)
            throws ConfigurationException {
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(realm)
                .setUriInfo(uriInfo)
                .setAccessCode(accessCode)
                .setClientSession(clientSession)
                .setUserSession(userSession)
                .setSession(session);
        return samlBuilder.build();
    }

    private AssertionType buildSAML20AssertionToken(UserSessionModel userSession, ClientSessionCode accessCode, AuthenticatedClientSessionModel clientSession)
            throws DatatypeConfigurationException {
        WSFedSAML2AssertionTypeBuilder samlBuilder = new WSFedSAML2AssertionTypeBuilder();
        samlBuilder.setRealm(realm)
                .setUriInfo(uriInfo)
                .setAccessCode(accessCode)
                .setClientSession(clientSession)
                .setUserSession(userSession)
                .setSession(session);
        return samlBuilder.build();
    }

    public WsFedSAMLAssertionTokenFormat getSamlAssertionTokenFormat(ClientModel client) {
        String value = client.getAttribute(WSFED_SAML_ASSERTION_TOKEN_FORMAT);
        try {
            if (value != null)
                return WsFedSAMLAssertionTokenFormat.parse(value);
            return WsFedSAMLAssertionTokenFormat.SAML20_ASSERTION_TOKEN_FORMAT;
        }
        catch(RuntimeException ex) {
            logger.error(ex.toString());
        }
        return WsFedSAMLAssertionTokenFormat.SAML20_ASSERTION_TOKEN_FORMAT;
    }

    protected boolean useJwt(ClientModel client) {
        return Boolean.parseBoolean(client.getAttribute(WSFED_JWT));
    }

    protected boolean isX5tIncluded(ClientModel client) {
        return Boolean.parseBoolean(client.getAttribute(WSFED_X5T));
    }

    @Override
    public void backchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        logger.debug("backchannelLogout");
        ClientModel client = clientSession.getClient();
        String redirectUri = null;
        if (client.getRedirectUris().size() > 0) {
            redirectUri = client.getRedirectUris().iterator().next();
        }
        String logoutUrl = RedirectUtils.verifyRedirectUri(uriInfo, redirectUri, realm, client);
        if (logoutUrl == null) {
            logger.warn("Can't do backchannel logout. No SingleLogoutService POST Binding registered for client: " + client.getClientId());
            return;
        }

        //Basically the same as SAML only we don't need to send an actual LogoutRequest. Just need to send the signoutcleanup1.0 action.
        HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();

        for (int i = 0; i < 2; i++) { // follow redirects once
            try {
                URIBuilder builder = new URIBuilder(logoutUrl);
                builder.addParameter(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION);
                builder.addParameter(WSFedConstants.WSFED_REALM, client.getClientId());
                HttpGet get = new HttpGet(builder.build());
                HttpResponse response = httpClient.execute(get);
                try {
                    int status = response.getStatusLine().getStatusCode();
                    if (status == 302  && !logoutUrl.endsWith("/")) {
                        String redirect = response.getFirstHeader(HttpHeaders.LOCATION).getValue();
                        String withSlash = logoutUrl + "/";
                        if (withSlash.equals(redirect)) {
                            logoutUrl = withSlash;
                            continue;
                        }
                    }
                } finally {
                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        InputStream is = entity.getContent();
                        if (is != null) is.close();
                    }

                }
            } catch (Exception e) {
                logger.warn("failed to send ws-fed logout to RP", e);
            }
            break;
        }
    }

    @Override
    public Response frontchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        logger.debug("frontchannelLogout");
        ClientModel client = clientSession.getClient();
        String redirectUri = null;
        if (!client.getRedirectUris().isEmpty()) {
            redirectUri = client.getRedirectUris().iterator().next();
        }
        String logoutUrl = RedirectUtils.verifyRedirectUri(uriInfo, redirectUri, realm, client);
        if (logoutUrl == null) {
            logger.error("Can't finish WS-Fed logout as there is no logout binding set. Has the redirect URI being used been added to the valid redirect URIs in the client?");
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.FAILED_LOGOUT);
        }

        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setAction(WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION)
                .setReplyTo(getEndpoint(uriInfo, realm))
                .setDestination(logoutUrl);

        return builder.buildResponse(null);
    }

    @Override
    public Response finishLogout(UserSessionModel userSession) {
        logger.debug("finishLogout");
        String logoutUrl = userSession.getNote(WSFED_LOGOUT_BINDING_URI);
        if (logoutUrl == null) {
            logger.error("Can't finish WS-Fed logout as there is no logout binding set. Has the redirect URI being used been added to the valid redirect URIs in the client?");
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.FAILED_LOGOUT);
        }

        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setContext(userSession.getNote(WSFED_CONTEXT))
                .setDestination(logoutUrl);

        return builder.buildResponse(null);
    }

    @Override
    public void close() {

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean requireReauthentication(UserSessionModel userSession, AuthenticationSessionModel authSession) {
        return false;
    }

    protected String getEndpoint(UriInfo uriInfo, RealmModel realm) {
        return uriInfo.getBaseUriBuilder()
                .path("realms").path(realm.getName())
                .path("protocol")
                .path(LOGIN_PROTOCOL)
                .build().toString();
    }
}
