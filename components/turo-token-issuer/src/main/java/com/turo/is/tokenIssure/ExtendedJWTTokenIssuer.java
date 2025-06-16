package com.turo.is.tokenIssure;

/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.util.ClaimHandlerUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.REQUEST_BINDING_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getPrivateKey;

/**
 * Extended JWT Token Issuer to extend issuing of refresh token in JWT format.
 */
public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {

    private static final String AUTHORIZED_ORGANIZATION_NAME_ATTRIBUTE = "org_name";
    private static final String AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE = "org_id";
    private static final String TOKEN_BINDING_REF = "binding_ref";
    private static final String TOKEN_BINDING_TYPE = "binding_type";
    private static final String AUTHORITIES_ATTRIBUTE = "authorities";
    private static final String INTERNAL_ATTRIBUTE = "Internal/";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String CLIENT_ID = "client_id";
    private static final String DEFAULT_TYP_HEADER_VALUE = "jwt";
    private static final String JWT_TYP_HEADER_VALUE = "jwt";
    private static final String CUSTOM_TOKEN_ATTR_TURO = "is_signup";
    private static final String SCOPE = "scope";
    private Algorithm signatureAlgorithm = null;
    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);

    public ExtendedJWTTokenIssuer() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    protected String buildJWTToken(OAuthTokenReqMessageContext request) throws IdentityOAuth2Exception{

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        List<JWTAccessTokenClaimProvider> claimProviders = getJWTAccessTokenClaimProviders();
        for (JWTAccessTokenClaimProvider claimProvider : claimProviders) {
            Map<String, Object> additionalClaims = claimProvider.getAdditionalClaims(request);

            if (additionalClaims != null) {
                //remove the claim org_name and org_id if exists
                additionalClaims.remove(AUTHORIZED_ORGANIZATION_NAME_ATTRIBUTE);
                additionalClaims.remove(AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE);

                additionalClaims.forEach(jwtClaimsSetBuilder::claim);
            }
        }

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = request.getOauth2AccessTokenReqDTO();
        String grantType = oAuth2AccessTokenReqDTO.getGrantType();

        RequestParameter[] requestParametersArray = oAuth2AccessTokenReqDTO.getRequestParameters();

        //adding additional properties in oauth2/token request to JWT.
        for (RequestParameter requestParameter : requestParametersArray) {
            String propertyKey = requestParameter.getKey();

            if (CUSTOM_TOKEN_ATTR_TURO.equals(propertyKey)) {
                jwtClaimsSetBuilder.claim(propertyKey, requestParameter.getValue()[0]);
            }
        }

        //fetch user roles and attach as claim authorities if grant type is client credentials
        if (grantType.equals(GRANT_TYPE_CLIENT_CREDENTIALS)) {
            int tenantId = getTenantId(request, null);
            String appClientId = oAuth2AccessTokenReqDTO.getClientId();

            String[] roles = getUserRoles(tenantId, appClientId);
            jwtClaimsSetBuilder.claim(AUTHORITIES_ATTRIBUTE, roles);
        }

        jwtClaimsSet = jwtClaimsSetBuilder.build();

        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWT(jwtClaimsSet, request, null);
    }

    @Override
    protected JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                             String consumerKey) throws IdentityOAuth2Exception {
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.claim(CLIENT_ID, consumerKey);

        String[] scope = getScope(authAuthzReqMessageContext, tokenReqMessageContext);
        if (scope != null || scope.length != 0) {
            jwtClaimsSetBuilder.claim(SCOPE, scope);
        }

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        OAuthAppDO oAuthAppDO = null;

        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey, tenantDomain);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        //setting exp in token
        long accessTokenLifeTimeInMillis;
        if (authAuthzReqMessageContext != null) {
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(authAuthzReqMessageContext, oAuthAppDO, consumerKey);
        } else {
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(tokenReqMessageContext, oAuthAppDO, consumerKey);
        }

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        jwtClaimsSetBuilder.expirationTime(calculateAccessTokenExpiryTime(accessTokenLifeTimeInMillis,
                curTimeInMillis));


        JWTClaimsSet jwtClaimsSet;

        // Handle custom claims
        if (authAuthzReqMessageContext != null) {
            jwtClaimsSet = handleCustomClaims(jwtClaimsSetBuilder, authAuthzReqMessageContext, oAuthAppDO);
        } else {
            jwtClaimsSet = handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext, oAuthAppDO);
        }

        if (tokenReqMessageContext != null && tokenReqMessageContext.getOauth2AccessTokenReqDTO() != null &&
                tokenReqMessageContext.getOauth2AccessTokenReqDTO().getAccessTokenExtendedAttributes() != null) {
            Map<String, String> customClaims =
                    tokenReqMessageContext.getOauth2AccessTokenReqDTO().getAccessTokenExtendedAttributes()
                            .getParameters();
            if (customClaims != null && !customClaims.isEmpty()) {
                for (Map.Entry<String, String> entry : customClaims.entrySet()) {
                    jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
                }
            }
        }

        // Include token binding.
        //jwtClaimsSet = handleTokenBinding(jwtClaimsSetBuilder, tokenReqMessageContext);

        return jwtClaimsSet;
    }

    @Override
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                    OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = resolveSigningTenantDomain(tokenContext, authorizationContext);
            //int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            int tenantId = getTenantId(tokenContext, authorizationContext);

            // Add claim with signer tenant to jwt claims set.
            jwtClaimsSet = setSignerRealm(tenantDomain, jwtClaimsSet);

            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder((JWSAlgorithm) signatureAlgorithm);
            Certificate certificate = OAuth2Util.getCertificate(tenantDomain, tenantId);
            String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
            headerBuilder.keyID(OAuth2Util.getKID(OAuth2Util.getCertificate(tenantDomain, tenantId),
                    (JWSAlgorithm) signatureAlgorithm, tenantDomain));

            if (authorizationContext != null && authorizationContext.isSubjectTokenFlow()) {
                headerBuilder.type(new JOSEObjectType(JWT_TYP_HEADER_VALUE));
            } else {
                // Set the required "typ" header "at+jwt" for access tokens issued by the issuer
                headerBuilder.type(new JOSEObjectType(DEFAULT_TYP_HEADER_VALUE));
            }
            headerBuilder.x509CertThumbprint(new Base64URL(certThumbPrint));
            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    private JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                            OAuthTokenReqMessageContext tokReqMsgCtx) {

        /**
         * If OAuth.JWT.RenewTokenWithoutRevokingExisting is enabled from configurations, and current token
         * binding is null,then we will add a new token binding (request binding) to the token binding with
         * a value of a random UUID.
         * The purpose of this new token binding type is to add a random value to the token binding so that
         * "User, Application, Scope, Binding" combination will be unique for each token.
         * Previously, if a token issue request come for the same combination of "User, Application, Scope, Binding",
         * the existing JWT token will be revoked and issue a new token. but with this way, we can issue new tokens
         * without revoking the old ones.
         *
         * Add following configuration to deployment.toml file to enable this feature.
         *     [oauth.jwt.renew_token_without_revoking_existing]
         *     enable = true
         *
         * By default, the allowed grant type for this feature is "client_credentials". If you need to enable for
         * other grant types, add the following configuration to deployment.toml file.
         *     [oauth.jwt.renew_token_without_revoking_existing]
         *     enable = true
         *     allowed_grant_types = ["client_credentials","password", ...]
         */
        boolean renewWithoutRevokingExistingEnabled = Boolean.parseBoolean(IdentityUtil.
                getProperty(RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG));

        if (renewWithoutRevokingExistingEnabled && tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() == null) {
            if (OAuth2ServiceComponentHolder.getJwtRenewWithoutRevokeAllowedGrantTypes()
                    .contains(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
                String tokenBindingValue = UUID.randomUUID().toString();
                tokReqMsgCtx.setTokenBinding(
                        new TokenBinding(REQUEST_BINDING_TYPE, OAuth2Util.getTokenBindingReference(tokenBindingValue),
                                tokenBindingValue));
            }
        }

        if (tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() != null) {
            // Include token binding into the jwt token.
            String bindingType = tokReqMsgCtx.getTokenBinding().getBindingType();
            jwtClaimsSetBuilder.claim(TOKEN_BINDING_REF, tokReqMsgCtx.getTokenBinding().getBindingReference());
            jwtClaimsSetBuilder.claim(TOKEN_BINDING_TYPE, bindingType);
            if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType)) {
                String cnf = tokReqMsgCtx.getTokenBinding().getBindingValue();
                if (StringUtils.isNotBlank(cnf)) {
                    jwtClaimsSetBuilder.claim(OAuthConstants.CNF, Collections.singletonMap(OAuthConstants.X5T_S256,
                            tokReqMsgCtx.getTokenBinding().getBindingValue()));
                }
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    private JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                            OAuthAuthzReqMessageContext authzReqMessageContext, OAuthAppDO oAuthAppDO)
            throws IdentityOAuth2Exception {

        CustomClaimsCallbackHandler claimsCallBackHandler = ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO);
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, authzReqMessageContext);
    }

    private JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                            OAuthTokenReqMessageContext tokenReqMessageContext, OAuthAppDO oAuthAppDO)
            throws IdentityOAuth2Exception {

        if (tokenReqMessageContext != null && tokenReqMessageContext.isPreIssueAccessTokenActionsExecuted()) {
            return handleCustomClaimsInPreIssueAccessTokenResponse(jwtClaimsSetBuilder, tokenReqMessageContext);
        }

        if (tokenReqMessageContext != null && tokenReqMessageContext.getOauth2AccessTokenReqDTO() != null &&
                shouldSkipOIDCClaimHandling(tokenReqMessageContext)) {
            /*
            CC grant and organization switch done from CC grant based token doesn't involve a user and hence skipping
            OIDC claims those cases.
             */
            return jwtClaimsSetBuilder.build();
        }

        CustomClaimsCallbackHandler claimsCallBackHandler = ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO);
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);
    }

    private JWTClaimsSet handleCustomClaimsInPreIssueAccessTokenResponse(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                                                         OAuthTokenReqMessageContext
                                                                                 tokenReqMessageContext) {

        Map<String, Object> customClaims = tokenReqMessageContext.getAdditionalAccessTokenClaims();

        if (customClaims != null) {
            if (log.isDebugEnabled()) {
                log.debug("Pre issue access token actions are executed. " +
                        "Returning the customized claim set from actions. Claims: " + customClaims.keySet());
            }

            customClaims.forEach(jwtClaimsSetBuilder::claim);
        }

        return jwtClaimsSetBuilder.build();
    }

    private boolean shouldSkipOIDCClaimHandling(OAuthTokenReqMessageContext tokenReqMessageContext) {

        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        // Check if the grant type is CLIENT_CREDENTIALS and the config to skip OIDC claims is enabled.
        boolean isSkipOIDCClaimsForClientCredentialGrant =
                OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(grantType) &&
                        OAuthServerConfiguration.getInstance().isSkipOIDCClaimsForClientCredentialGrant();
        // Check if the grant type is ORGANIZATION_SWITCH and the user type is APPLICATION
        boolean isOrgSwitchWithAppUser = OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(grantType) &&
                OAuthConstants.UserType.APPLICATION.equals(getAuthorizedUserType(null, tokenReqMessageContext));

        return isSkipOIDCClaimsForClientCredentialGrant || isOrgSwitchWithAppUser;
    }

    private String getAuthorizedUserType(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                         OAuthTokenReqMessageContext tokenReqMessageContext) {

        if (tokenReqMessageContext != null) {
            return (String) tokenReqMessageContext.getProperty(OAuthConstants.UserType.USER_TYPE);
        } else {
            return (String) authAuthzReqMessageContext.getProperty(OAuthConstants.UserType.USER_TYPE);
        }
    }

    private String resolveSigningTenantDomain(OAuthTokenReqMessageContext tokenContext,
                                              OAuthAuthzReqMessageContext authorizationContext)
            throws IdentityOAuth2Exception {

        String clientID;
        AuthenticatedUser authenticatedUser;
        if (authorizationContext != null) {
            clientID = authorizationContext.getAuthorizationReqDTO().getConsumerKey();
            authenticatedUser = authorizationContext.getAuthorizationReqDTO().getUser();
        } else if (tokenContext != null) {
            clientID = tokenContext.getOauth2AccessTokenReqDTO().getClientId();
            authenticatedUser = tokenContext.getAuthorizedUser();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Empty OAuthTokenReqMessageContext and OAuthAuthzReqMessageContext. Therefore, could " +
                        "not determine the tenant domain to sign the request.");
            }
            throw new IdentityOAuth2Exception("Could not determine the authenticated user and the service provider");
        }
        return getSigningTenantDomain(clientID, authenticatedUser);
    }

    private static List<JWTAccessTokenClaimProvider> getJWTAccessTokenClaimProviders() {

        return OAuth2ServiceComponentHolder.getInstance().getJWTAccessTokenClaimProviders();
    }

    private String getSigningTenantDomain(String clientID, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        String tenantDomain;
        String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        /*
         If applicationResidentOrgId is not empty, then the request comes for an application which is registered
         directly in the organization of the applicationResidentOrgId. In this scenario, the signing tenant domain
         should be the root tenant domain of the applicationResidentOrgId.
        */
        if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
            tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        } else if (OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
            if (log.isDebugEnabled()) {
                log.debug("Using the tenant domain of the SP to sign the token");
            }
            if (StringUtils.isBlank(clientID)) {
                throw new IdentityOAuth2Exception("Empty ClientId. Cannot resolve the tenant domain to sign the token");
            }
            try {
                tenantDomain = OAuth2Util.getAppInformationByClientId(clientID).getAppOwner().getTenantDomain();
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error occurred while getting the application information by client" +
                        " id: " + clientID, e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Using the tenant domain of the user to sign the token");
            }
            if (authenticatedUser == null) {
                throw new IdentityOAuth2Exception(
                        "Authenticated user is not set. Cannot resolve the tenant domain to sign the token");
            }
            tenantDomain = authenticatedUser.getTenantDomain();
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw new IdentityOAuth2Exception("Cannot resolve the tenant domain to sign the token");
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Tenant domain: %s will be used to sign the token for the authenticated " +
                    "user: %s", tenantDomain, authenticatedUser.toFullQualifiedUsername()));
        }
        return tenantDomain;
    }

    private JWTClaimsSet setSignerRealm(String tenantDomain, JWTClaimsSet jwtClaimsSet) {

        Map<String, String> realm = new HashMap<>();
        if (!OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
            realm.put(OAuthConstants.OIDCClaims.SIGNING_TENANT, tenantDomain);
        }
        if (realm.size() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Setting authorized user tenant domain : " + tenantDomain +
                        " used for signing the token to the 'realm' claim of jwt token");
            }
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
            jwtClaimsSetBuilder.claim(OAuthConstants.OIDCClaims.REALM, realm);
            jwtClaimsSet = jwtClaimsSetBuilder.build();
        }
        return jwtClaimsSet;
    }

    private String[] getUserRoles(int tenantId, String username) {

        RealmService realmService = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(RealmService.class, null);

        UserRealm userRealm = null;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            String[] roles = userStoreManager.getRoleListOfUser(username);
            roles = removeInternalFromRoles(roles);
            return roles;
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving user roles " + e);
            }

            return new String[0];
        }
    }

    private String[] removeInternalFromRoles(String[] roles) {
        roles = Arrays.stream(roles)
                .map(s -> s.startsWith(INTERNAL_ATTRIBUTE) ? s.substring(INTERNAL_ATTRIBUTE.length()) : s)
                .toArray(String[]::new);

        return roles;
    }

    private int getTenantId(OAuthTokenReqMessageContext tokenContext,
                            OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        String tenantDomain = resolveSigningTenantDomain(tokenContext, authorizationContext);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        return tenantId;
    }

    private Date calculateAccessTokenExpiryTime(Long accessTokenLifeTimeInMillis, Long curTimeInMillis) {

        Date expirationTime;
        // When accessTokenLifeTimeInMillis is equal to Long.MAX_VALUE the curTimeInMillis +
        // accessTokenLifeTimeInMillis can be a negative value
        if (curTimeInMillis + accessTokenLifeTimeInMillis < curTimeInMillis) {
            expirationTime = new Date(Long.MAX_VALUE);
        } else {
            expirationTime = new Date(curTimeInMillis + accessTokenLifeTimeInMillis);
        }
        if (log.isDebugEnabled()) {
            log.debug("Access token expiry time : " + expirationTime + "ms.");
        }
        return expirationTime;
    }

    private String[] getScope(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        String[] scope;
        String scopeString = null;
        if (tokenReqMessageContext != null) {
            scope = tokenReqMessageContext.getScope();
        } else {
            scope = authAuthzReqMessageContext.getApprovedScope();
        }
//        if (ArrayUtils.isNotEmpty(scope)) {
//            scopeString = OAuth2Util.buildScopeString(scope);
//            if (log.isDebugEnabled()) {
//                log.debug("Scope exist for the jwt access token with subject " + getAuthenticatedSubjectIdentifier(
//                        authAuthzReqMessageContext, tokenReqMessageContext) + " and the scope is " + scopeString);
//            }
//        }
        //return scopeString;
        return scope;
    }

    private String getAuthenticatedSubjectIdentifier(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                     OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext);
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }

    private AuthenticatedUser getAuthenticatedUser(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                   OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {
        AuthenticatedUser authenticatedUser;
        if (authAuthzReqMessageContext != null) {
            authenticatedUser = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
        } else {
            authenticatedUser = tokenReqMessageContext.getAuthorizedUser();
        }

        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception("Authenticated user is null for the request.");
        }
        return authenticatedUser;
    }
}