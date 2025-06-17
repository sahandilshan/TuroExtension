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
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
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
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getPrivateKey;

public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {

    private static final String AUTHORIZED_ORGANIZATION_NAME_ATTRIBUTE = "org_name";
    private static final String AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE = "org_id";
    private static final String AUTHORITIES_ATTRIBUTE = "authorities";
    private static final String INTERNAL_ATTRIBUTE = "Internal/";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String DEFAULT_TYP_HEADER_VALUE = "jwt";
    private static final String JWT_TYP_HEADER_VALUE = "jwt";
    private static final String CUSTOM_TOKEN_ATTR_TURO = "is_signup";
    private static final String CLAIM_SCOPE = "scope";
    private static final String CLAIM_AUT = "aut";
    private static final String CLAIM_AZP = "azp";
    private static final String ROLE_EVERYONE = "everyone";

    private Algorithm signatureAlgorithm = null;
    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);

    public ExtendedJWTTokenIssuer() throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug("Custom JWT Access token builder is initiated");
        }
        signatureAlgorithm = mapSignatureAlgorithm(OAuthServerConfiguration.getInstance().getSignatureAlgorithm());
    }

    private String[] getRolesForClientCredentials(OAuthTokenReqMessageContext request,
                                                  OAuth2AccessTokenReqDTO dto) throws IdentityOAuth2Exception {
        if (GRANT_TYPE_CLIENT_CREDENTIALS.equals(dto.getGrantType())) {
            int tenantId = getTenantId(request, null);
            String[] roles = getUserRoles(tenantId, dto.getClientId());
            return roles;
        }
        return new String[0];
    }

    private void addCustomAttributes(OAuth2AccessTokenReqDTO dto, JWTClaimsSet.Builder builder) {
        Arrays.stream(dto.getRequestParameters())
                .filter(param -> CUSTOM_TOKEN_ATTR_TURO.equals(param.getKey()))
                .findFirst()
                .ifPresent(param -> builder.claim(param.getKey(), param.getValue()[0]));
    }

    private void removeValues(JWTClaimsSet.Builder builder) {
        builder.issuer(null)
                .subject(null)
                .notBeforeTime(null)
                .audience((String) null)
                .claim(CLAIM_AUT, null)
                .claim(CLAIM_AZP, null)
                .claim(AUTHORIZED_ORGANIZATION_ID_ATTRIBUTE, null)
                .claim(AUTHORIZED_ORGANIZATION_NAME_ATTRIBUTE, null);
    }

    private void modifyAuthoritiesAndScopes(JWTClaimsSet.Builder builder, JWTClaimsSet claimsSet, String[] roles) {
        handleScopeClaim(builder, claimsSet.getClaim(CLAIM_SCOPE));
        handleAuthoritiesClaim(builder, claimsSet.getClaim(AUTHORITIES_ATTRIBUTE), roles);
    }

    private void handleScopeClaim(JWTClaimsSet.Builder builder, Object scopeObj) {
        if (scopeObj instanceof String) {
            String scopeStr = (String) scopeObj;
            if (!StringUtils.isEmpty(scopeStr)) {
                builder.claim(CLAIM_SCOPE, scopeStr.split(" "));
            } else {
                builder.claim(CLAIM_SCOPE, null);
            }
        } else {
            builder.claim(CLAIM_SCOPE, null);
        }
    }

    private void handleAuthoritiesClaim(JWTClaimsSet.Builder builder, Object authoritiesObj, String[] roles) {
        if (authoritiesObj instanceof JSONArray) {
            JSONArray authoritiesArray = (JSONArray) authoritiesObj;
            for (int i = 0; i < authoritiesArray.size(); i++) {
                authoritiesArray.set(i, authoritiesArray.get(i).toString().replace(INTERNAL_ATTRIBUTE, ""));
            }
            authoritiesArray.remove(ROLE_EVERYONE);
            builder.claim(AUTHORITIES_ATTRIBUTE, authoritiesArray);
        } else if (authoritiesObj instanceof String) {
            String authority = (String) authoritiesObj;
            if (authority.contains(ROLE_EVERYONE)) {
                builder.claim(AUTHORITIES_ATTRIBUTE, null);
            } else {
                builder.claim(AUTHORITIES_ATTRIBUTE, authority.replace(INTERNAL_ATTRIBUTE, ""));
            }
        } else if (roles != null && roles.length > 0) {
            List<String> filtered = Arrays.stream(roles)
                    .map(role -> role.replace(INTERNAL_ATTRIBUTE, ""))
                    .collect(Collectors.toList());
            filtered.remove(ROLE_EVERYONE);
            builder.claim(AUTHORITIES_ATTRIBUTE, filtered.toArray(new String[0]));
        }
    }

    @Override
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                    OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        try {
            jwtClaimsSet = modifyBeforeSigning(jwtClaimsSet, tokenContext, authorizationContext);
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

    private JWTClaimsSet modifyBeforeSigning(JWTClaimsSet jwtClaimsSet,
                                             OAuthTokenReqMessageContext tokenContext,
                                             OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {
        OAuth2AccessTokenReqDTO dto = tokenContext.getOauth2AccessTokenReqDTO();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(jwtClaimsSet);
        removeValues(builder);
        String[] roles = getRolesForClientCredentials(tokenContext, dto);
        addCustomAttributes(dto, builder);
        modifyAuthoritiesAndScopes(builder, jwtClaimsSet, roles);
        return builder.build();
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
        try {
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            return userRealm.getUserStoreManager().getRoleListOfUser(username);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving user roles", e);
            }
            return new String[0];
        }
    }

    private int getTenantId(OAuthTokenReqMessageContext tokenContext,
                            OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        String tenantDomain = resolveSigningTenantDomain(tokenContext, authorizationContext);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        return tenantId;
    }
}
