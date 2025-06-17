package com.turo.custom.grant.handler;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;

import java.text.ParseException;

public class JwtRefreshGrantHandler extends RefreshGrantHandler {

    private static final Log log = LogFactory.getLog(JwtRefreshGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        handleJWTRefreshToken(tokReqMsgCtx.getOauth2AccessTokenReqDTO());
        return super.validateGrant(tokReqMsgCtx);
    }

    /**
     * Handles JWT refresh tokens by extracting the JTI claim if the refresh token is a JWT.
     * If the refresh token is not a JWT, it remains unchanged.
     *
     * @param tokenReq The OAuth2 access token request DTO containing the refresh token
     * @throws IdentityOAuth2Exception If an error occurs while processing the JWT token
     */
    private void handleJWTRefreshToken(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {

        String refreshToken = tokenReq.getRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            return;
        }

        // Check if the refresh token is a JWT
        if (JWTUtils.isJWT(refreshToken)) {
            try {
                // Parse the JWT token
                SignedJWT signedJWT = JWTUtils.parseJWT(refreshToken);
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                // Extract the JTI claim
                String jti = claimsSet.getJWTID();
                if (jti != null && !jti.isEmpty()) {
                    // Set the refresh token to the JTI
                    tokenReq.setRefreshToken(jti);
                    if (log.isDebugEnabled()) {
                        log.debug("Extracted JTI from JWT refresh token for client: " + tokenReq.getClientId());
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("JWT refresh token does not contain JTI claim for client: " + tokenReq.getClientId());
                    }
                }
            } catch (ParseException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to parse JWT refresh token for client: " + tokenReq.getClientId() +
                            ". Using original token.", e);
                }
                // If parsing fails, continue with the original token
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error processing JWT refresh token for client: " + tokenReq.getClientId() +
                            ". Using original token.", e);
                }
                // If any other error occurs, continue with the original token.
            }
        }
    }
}
