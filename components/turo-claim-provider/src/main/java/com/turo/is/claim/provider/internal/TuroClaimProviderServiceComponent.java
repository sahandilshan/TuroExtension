package com.turo.is.claim.provider.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;
import com.turo.is.claim.provider.TuroClaimProvider;

@Component(
        name = "identity.turo.claim.provider.component",
        immediate = true
)
public class TuroClaimProviderServiceComponent {

    private static final Log LOG = LogFactory.getLog(TuroClaimProviderServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            TuroClaimProvider turoClaimProvider = new TuroClaimProvider();
            context.getBundleContext()
                    .registerService(ClaimProvider.class, turoClaimProvider, null);
            context.getBundleContext()
                    .registerService(JWTAccessTokenClaimProvider.class, turoClaimProvider, null);
        } catch (Exception e) {
            LOG.error("Error when registering OrganizationClaimProvider service.", e);
        }
        LOG.debug("OrganizationClaimProvider bundle is activated successfully.");
    }
}
