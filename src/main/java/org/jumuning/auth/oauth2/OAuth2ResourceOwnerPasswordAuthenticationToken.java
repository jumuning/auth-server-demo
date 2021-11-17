package org.jumuning.auth.oauth2;

import java.util.*;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * @author jumuning
 * @date 2021/9/14
 * OAuth2 资源所有者密码认证令牌
 */
public class OAuth2ResourceOwnerPasswordAuthenticationToken extends AbstractAuthenticationToken {

        private static final long serialVersionUID = -6067207202119450764L;

        private final AuthorizationGrantType authorizationGrantType;
        private final Authentication clientPrincipal;
        private final Set<String> scopes;
        private final Map<String, Object> additionalParameters;

        /**
         * Constructs an {@code OAuth2ClientCredentialsAuthenticationToken} using the provided parameters.
         *
         * @param principal the authenticated client principal
         */

        public OAuth2ResourceOwnerPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                                              Authentication principal, @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
            super(Collections.emptyList());
            Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
            Assert.notNull(principal, "clientPrincipal cannot be null");
            this.authorizationGrantType = authorizationGrantType;
            this.clientPrincipal = principal;
            this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
            this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
        }

        /**
         * Returns the authorization grant type.
         *
         * @return the authorization grant type
         */
        public AuthorizationGrantType getGrantType() {
            return this.authorizationGrantType;
        }

        @Override
        public Object getPrincipal() {
            return this.clientPrincipal;
        }

        @Override
        public Object getCredentials() {
            return "";
        }

        /**
         * Returns the requested scope(s).
         *
         * @return the requested scope(s), or an empty {@code Set} if not available
         */
        public Set<String> getScopes() {
            return this.scopes;
        }

        /**
         * Returns the additional parameters.
         *
         * @return the additional parameters
         */
        public Map<String, Object> getAdditionalParameters() {
            return this.additionalParameters;
        }

}
