/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.oauth2login;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.annotations.VisibleForTesting;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.User;
import hudson.model.Descriptor.FormException;
import hudson.security.SecurityRealm;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.Stapler;

import java.io.IOException;
import java.util.Arrays;
import java.util.StringTokenizer;
import java.util.Base64;
import com.google.gson.Gson;
import java.util.logging.Logger;
import java.util.logging.Level;

import jenkins.model.Jenkins;
/**
 * Login with OAuth 2
 *
 */
public class GoogleOAuth2SecurityRealm extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(GoogleOAuth2SecurityRealm.class.getName());

    /**
     * OAuth 2 scope. This is enough to call a variety of userinfo api's.
     */
    private static final String SCOPE = "profile email";

    /**
     * Global instance of the JSON factory.
     */
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    private static final String SESSION_NAME = GoogleOAuth2SecurityRealm.class.getName() + ".OAuthSession";

    /**
     * The clientID.
     */
    private final String clientId;
    /**
     * The client secret.
     */
    private final Secret clientSecret;

    /**
     * If this is non-null, access will be restricted to this domain.
     */
    private final String domain;

    /**
     * If true, the redirection will happen based on the root URL determined from request.
     * If false, the redirection will happen based on the root URL configured in Jenkins.
     */
    private boolean rootURLFromRequest;

    private boolean debug;

    private String authorizationEndpointUrl;
    private String tokenEndpointUrl;
    private String userInfoEndpointUrl;

    @DataBoundConstructor
    public GoogleOAuth2SecurityRealm(String clientId, String clientSecret, String domain, 
                                     String authorizationEndpointUrl, String tokenEndpointUrl, String userInfoEndpointUrl) throws IOException {
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        this.domain = Util.fixEmptyAndTrim(domain);
        this.authorizationEndpointUrl = authorizationEndpointUrl;
        this.tokenEndpointUrl = tokenEndpointUrl;
        this.userInfoEndpointUrl = userInfoEndpointUrl;
        this.debug = false; // 设置默认值为 false
    }

    @SuppressWarnings("unused") // jelly
    public boolean isRootURLFromRequest() {
        return rootURLFromRequest;
    }

    @DataBoundSetter
    @SuppressWarnings("unused") // jelly
    public void setRootURLFromRequest(boolean rootURLFromRequest) {
        this.rootURLFromRequest = rootURLFromRequest;
    }
    
    public boolean isDebug() {
        return debug;
    }

    @DataBoundSetter
    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    @SuppressWarnings("unused") // jelly
    public String getClientId() {
        return clientId;
    }

    @SuppressWarnings("unused") // jelly
    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getDomain() {
        return domain;
    }

    public String getAuthorizationEndpointUrl() {
        return authorizationEndpointUrl;
    }

    public String getTokenEndpointUrl() {
        return tokenEndpointUrl;
    }

    public String getUserInfoEndpointUrl() {
        return userInfoEndpointUrl;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(StaplerRequest, String,String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    /**
     * Acegi has this notion that first an {@link org.acegisecurity.Authentication} object is created
     * by collecting user information and then the act of authentication is done
     * later (by {@link org.acegisecurity.AuthenticationManager}) to verify it. But in case of OpenID,
     * we create an {@link org.acegisecurity.Authentication} only after we verified the user identity,
     * so {@link org.acegisecurity.AuthenticationManager} becomes no-op.
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof AnonymousAuthenticationToken)
                            return authentication;
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                }
        );
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        return "securityRealm/loggedOut";
    }

    public void configure(StaplerRequest req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        try {
            Jenkins.get().save();
        } catch (IOException e) {
            throw new FormException("Failed to save configuration", e, "");
        }
    }
    /**
     * The login process starts from here.
     */
    @SuppressWarnings("unused") // stapler
    @Restricted(DoNotUse.class) // stapler only
    public HttpResponse doCommenceLogin(StaplerRequest request, @QueryParameter String from,  @Header("Referer") final String referer) throws IOException {
        final String redirectOnFinish = getRedirectOnFinish(from, referer);

        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.authorizationHeaderAccessMethod(),
                HTTP_TRANSPORT,
                JSON_FACTORY,
                new GenericUrl(tokenEndpointUrl),
                new ClientParametersAuthentication(clientId, clientSecret.getPlainText()),
                clientId,
                authorizationEndpointUrl)
                .setScopes(Arrays.asList(SCOPE))
                .build();

        OAuthSession oAuthSession = new OAuthSession(from, buildOAuthRedirectUrl(), domain, debug) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {
                    if (debug) {
                        LOGGER.info("Requesting access_token");
                        LOGGER.info("URL: " + tokenEndpointUrl);
                        LOGGER.info("client_id: " + clientId);
                        LOGGER.info("client_secret: " + clientSecret.getPlainText());
                        LOGGER.info("grant_type: authorization_code");
                        try {
                            Base64.getDecoder().decode(authorizationCode);
                            LOGGER.info("Authorization code is valid Base64");
                        } catch (IllegalArgumentException e) {
                            LOGGER.info("Authorization code is not valid Base64");
                        }
                        LOGGER.info("code: " + authorizationCode);
                    }
                    TokenResponse response = flow.newTokenRequest(authorizationCode)
                            .setRedirectUri(buildOAuthRedirectUrl())
                            .execute();
                    if (debug) {
                        LOGGER.info("Token response: " + new Gson().toJson(response));
                        LOGGER.info("redirect_uri: " + buildOAuthRedirectUrl());
                    }

                    final Credential credential = flow.createAndStoreCredential(response, null);
                    if (debug) {
                        LOGGER.info("Credential created: " + credential.getAccessToken());
                    }

                    HttpRequestFactory requestFactory =
                            HTTP_TRANSPORT.createRequestFactory(new HttpRequestInitializer() {
                                public void initialize(HttpRequest request) throws IOException {
                                    credential.initialize(request);
                                    request.setParser(new JsonObjectParser(JSON_FACTORY));
                                }
                            });
                    GenericUrl url = new GenericUrl(userInfoEndpointUrl);
                    url.set("access_token", credential.getAccessToken());

                    HttpRequest request = requestFactory.buildGetRequest(url);
                    if (debug) {
                        LOGGER.info("Sending request to: " + url);
                        LOGGER.info("Request headers: " + request.getHeaders().toString());
                    }

                    GoogleUserInfo info = request.execute().parseAs(GoogleUserInfo.class);

                    if (debug) {
                        LOGGER.info("Received user info: " + new Gson().toJson(info));
                    }
                    if (info.hasError()) {
                        if (debug) {
                            LOGGER.info("Error in user info: " + info.getErrorMessage());
                        }
                        return HttpResponses.error(info.code, "Error from provider: " + info.getErrorMessage());
                    }
                    
                    if (info.getEmail() == null) {
                        return HttpResponses.errorWithoutStack(401, "Email information is missing");
                    }

                    if (info.getEmail() == null) {
                        return HttpResponses.errorWithoutStack(401, "Email information is missing");
                    }
                    
                    String[] emailParts = info.getEmail().split("@");
                    if (emailParts.length != 2) {
                        return HttpResponses.errorWithoutStack(401, "Invalid email format");
                    }
                    
                    if (!isDomainValid(info.getEmail().split("@")[1])) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }
                    
                    GrantedAuthority[] authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
                    // logs this user in.
                    UsernamePasswordAuthenticationToken token =
                            new UsernamePasswordAuthenticationToken(info.getEmail(), "", authorities);

                    // prevent session fixation attack
                    Stapler.getCurrentRequest().getSession().invalidate();
                    Stapler.getCurrentRequest().getSession();

                    SecurityContextHolder.getContext().setAuthentication(token);
                    // update the user profile.
                    User u = User.get(token.getName());
                    info.updateProfile(u);
                    // fire "LoggedIn" and not "authenticated" because
                    // "authenticated" is "Fired when a user was successfully authenticated by password."
                    // which is less relevant in our case
                    SecurityListener.fireLoggedIn(token.getName());
                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    if (debug) {
                        LOGGER.log(Level.SEVERE, "Error while requesting token", e);
                    }
                    return HttpResponses.error(500, e);
                }

            }
        };
        request.getSession().setAttribute(SESSION_NAME, oAuthSession);
        return oAuthSession.doCommenceLogin(flow);
    }

    String getRedirectOnFinish(String from, String referer) {
        final String redirectOnFinish;
        if (from != null && Util.isSafeToRedirectTo(from)) {
            redirectOnFinish = from;
        } else if (referer != null && Util.isSafeToRedirectTo(referer)) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = getRootURL();
        }
        return redirectOnFinish;
    }

    @VisibleForTesting
    boolean isDomainValid(Object tokenDomain) {
        if (domain == null) {
            return true;
        }
        StringTokenizer tokenizer = new StringTokenizer(domain, ",");
        while (tokenizer.hasMoreElements()) {
            String domainToTest = tokenizer.nextToken().trim();
            if (domainToTest.equals(tokenDomain)) {
                return true;
            }
        }
        return false;
    }

    private String buildOAuthRedirectUrl() {
        String rootUrl = getRootURL();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    private String getRootURL() {
        if (rootURLFromRequest) {
            return Jenkins.getInstance().getRootUrlFromRequest();
        } else {
            return Jenkins.getInstance().getRootUrl();
        }
    }


    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    @SuppressWarnings("unused") // stapler
    @Restricted(DoNotUse.class) // stapler only
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        OAuthSession oAuthSession = (OAuthSession) request.getSession().getAttribute(SESSION_NAME);
        if (oAuthSession != null) {
            if (debug) {
                String jsonResponse = new Gson().toJson(request.getParameterMap());
                LOGGER.info("OAuthSession found, proceeding with doFinishLogin. Request data: " + jsonResponse);
                LOGGER.info("Client ID: " + clientId);
                LOGGER.info("Redirect URI: " + buildOAuthRedirectUrl());
            }
            try {
                return oAuthSession.doFinishLogin(request);
            } catch (Exception e) {
                if (debug) {
                    LOGGER.log(Level.SEVERE, "Exception occurred during doFinishLogin", e);
                }
                throw e;
            }
        } else {
            if (debug) {
                String jsonResponse = new Gson().toJson(request.getParameterMap());
                LOGGER.info("OAuthSession not found, session expired. Request data: " + jsonResponse);
            }
            return new Failure("Your Jenkins session has expired. Please login again.");
        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Login with OAuth2.0";
        }
    }
}
