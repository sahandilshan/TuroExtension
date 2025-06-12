package com.turo.is.claim.provider;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;

import java.util.HashMap;
import java.util.Map;

public class TuroClaimProvider implements ClaimProvider, JWTAccessTokenClaimProvider {

    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String CLIENT_CREDENTIALS_CLAIM =  "client_credentials_claim";
    private static final String CUSTOM_TOKEN_ATTR_TURO = "is_signup";

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) throws IdentityOAuth2Exception {
        return new HashMap<>();
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {
        return addClientCredClaims(oAuthTokenReqMessageContext);
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext, OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO) throws IdentityOAuth2Exception {
        return new HashMap<>();
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext oAuthTokenReqMessageContext, OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO) throws IdentityOAuth2Exception {
        return new HashMap<>();
    }

    private Map<String, Object> addClientCredClaims(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) {

        Map<String, Object> additionalClaims = new HashMap<>();
        String grantType = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        RequestParameter[] requestParametersArray = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getRequestParameters();

        //adding property value based on the grant type
        if (grantType.equals(GRANT_TYPE_CLIENT_CREDENTIALS)) {
            additionalClaims.put(CLIENT_CREDENTIALS_CLAIM, "true");
        } else {
            additionalClaims.put(CLIENT_CREDENTIALS_CLAIM, "false");
        }

        //adding additional properties in oauth2/token request to JWT.
        for (RequestParameter requestParameter : requestParametersArray) {
            String propertyKey = requestParameter.getKey();

            if (CUSTOM_TOKEN_ATTR_TURO.equals(propertyKey)) {
                additionalClaims.put(propertyKey, requestParameter.getValue()[0]);
            }
        }

        return additionalClaims;
    }
}
