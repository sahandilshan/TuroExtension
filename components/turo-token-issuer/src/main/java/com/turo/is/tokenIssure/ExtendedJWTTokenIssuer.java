package com.turo.is.tokenIssure;

/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com)
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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getPrivateKey;

/**
 * Extended JWT Token Issuer to extend issuing of refresh token in JWT format.
 */
public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {

    private static final String AUDIENCE = "aud";
    private static final String AUTHORIZED_ORGANIZATION_NAME_ATTRIBUTE = "org_name";
    private static final String AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE = "org_id";

    private static final String AUTHORITIES_ATTRIBUTE = "authorities";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String DEFAULT_TYP_HEADER_VALUE = "jwt";
    private static final String JWT_TYP_HEADER_VALUE = "jwt";
    private static final String TURO_ID_ATTRIBUTE = "turo_id";

    private static final String CUSTOM_TOKEN_ATTR_TURO = "is_signup";
    private Algorithm signatureAlgorithm = null;
    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);

    public ExtendedJWTTokenIssuer() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        if (config == null) {
            throw new IdentityOAuth2Exception("OAuthServerConfiguration instance is null");
        }

        String configuredAlgorithm = config.getSignatureAlgorithm();
        if (configuredAlgorithm == null) {
            throw new IdentityOAuth2Exception("Signature algorithm is not configured in OAuthServerConfiguration");
        }

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(configuredAlgorithm);
        if (signatureAlgorithm == null) {
            throw new IdentityOAuth2Exception("Failed to map signature algorithm: " + configuredAlgorithm);
        }
    }

    @Override
    protected String buildJWTToken(OAuthTokenReqMessageContext request) throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        if (request.getScope() != null && Arrays.asList((request.getScope())).contains(AUDIENCE)) {
            jwtClaimsSetBuilder.audience(Arrays.asList(request.getScope()));
        }

        List<JWTAccessTokenClaimProvider> claimProviders = getJWTAccessTokenClaimProviders();
        for (JWTAccessTokenClaimProvider claimProvider : claimProviders) {
            Map<String, Object> additionalClaims = claimProvider.getAdditionalClaims(request);

            if (additionalClaims != null) {
                // Remove the claim org_name if exists.
                additionalClaims.remove(AUTHORIZED_ORGANIZATION_NAME_ATTRIBUTE);

                // Rename org_id to turo_id.
                if (additionalClaims.containsKey(AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE)) {
                    //String orgId = String.valueOf(additionalClaims.get(AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE));
                    String orgId = String.valueOf(additionalClaims.remove(AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE));
                    additionalClaims.put(TURO_ID_ATTRIBUTE, orgId);
                }
                additionalClaims.forEach(jwtClaimsSetBuilder::claim);
            }
        }

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = request.getOauth2AccessTokenReqDTO();
        String grantType = oAuth2AccessTokenReqDTO.getGrantType();

        RequestParameter[] requestParametersArray = oAuth2AccessTokenReqDTO.getRequestParameters();

        // Adding additional properties in oauth2/token request to JWT.
        if (requestParametersArray != null) {
            for (RequestParameter requestParameter : requestParametersArray) {
                if (requestParameter != null) {
                    String propertyKey = requestParameter.getKey();

                    if (CUSTOM_TOKEN_ATTR_TURO.equals(propertyKey) && requestParameter.getValue() != null 
                            && requestParameter.getValue().length > 0) {
                        jwtClaimsSetBuilder.claim(propertyKey, requestParameter.getValue()[0]);
                    }
                }
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
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                    OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = resolveSigningTenantDomain(tokenContext, authorizationContext);
            //int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            int tenantId = getTenantId(tokenContext, authorizationContext);

            // Add claim with signer tenant to jwt claims set.
            jwtClaimsSet = setSignerRealm(tenantDomain, jwtClaimsSet);

            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            if (privateKey == null) {
                throw new IdentityOAuth2Exception("Private key is null for tenant domain: " + tenantDomain);
            }
            
            if (signatureAlgorithm == null) {
                throw new IdentityOAuth2Exception("Signature algorithm is not configured");
            }
            
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder((JWSAlgorithm) signatureAlgorithm);
            
            Certificate certificate = OAuth2Util.getCertificate(tenantDomain, tenantId);
            if (certificate == null) {
                throw new IdentityOAuth2Exception("Certificate is null for tenant domain: " + tenantDomain);
            }
            
            String certThumbPrint = OAuth2Util.getThumbPrint(certificate);

            headerBuilder.keyID(OAuth2Util.getKID(OAuth2Util.getCertificate(tenantDomain, tenantId),
                    (JWSAlgorithm) signatureAlgorithm, tenantDomain));

            if (authorizationContext != null && authorizationContext.isSubjectTokenFlow()) {
                headerBuilder.type(new JOSEObjectType(JWT_TYP_HEADER_VALUE));
            } else {
                // Set the required "typ" header "at+jwt" for access tokens issued by the issuer.
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
                tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientID);
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
                    "user: %s", tenantDomain, (authenticatedUser != null ? authenticatedUser.toFullQualifiedUsername() : "null")));
        }
        return tenantDomain;
    }

    private JWTClaimsSet setSignerRealm(String tenantDomain, JWTClaimsSet jwtClaimsSet) {

        Map<String, String> realm = new HashMap<>();
        if (!OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
            realm.put(OAuthConstants.OIDCClaims.SIGNING_TENANT, tenantDomain);
        }
        if (!realm.isEmpty()) {
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

    private String[] getUserRoles(int tenantId, String username){

        RealmService realmService = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(RealmService.class, null);

        if (realmService == null) {
            log.warn("RealmService is null, returning empty roles array");
            return new String[0];
        }

        try {
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm == null) {
                log.warn("UserRealm is null for tenantId: " + tenantId + ", returning empty roles array");
                return new String[0];
            }
            
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                log.warn("UserStoreManager is null for tenantId: " + tenantId + ", returning empty roles array");
                return new String[0];
            }
            
            String[] roles = userStoreManager.getRoleListOfUser(username);
            if (roles == null) {
                log.warn("Roles array is null for username: " + username + ", returning empty roles array");
                return new String[0];
            }

            roles = Arrays.stream(roles)
                    .map(s -> s.startsWith("Internal/") ? s.substring("Internal/".length()) : s)
                    .toArray(String[]::new);

            return roles;
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while fetching user roles for username: " + username, e);
            }
            return new String[0];
        }
    }

    private int getTenantId(OAuthTokenReqMessageContext tokenContext,
                            OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        String tenantDomain = resolveSigningTenantDomain(tokenContext, authorizationContext);
        return IdentityTenantUtil.getTenantId(tenantDomain);
    }
}
