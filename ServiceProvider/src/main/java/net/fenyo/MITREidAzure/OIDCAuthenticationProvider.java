package net.fenyo.MITREidAzure;

import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;

import java.util.Collection;

import org.mitre.openid.connect.client.NamedAdminAuthoritiesMapper;
import org.mitre.openid.connect.client.OIDCAuthoritiesMapper;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;

public class OIDCAuthenticationProvider extends org.mitre.openid.connect.client.OIDCAuthenticationProvider {

	private OIDCAuthoritiesMapper authoritiesMapper = new NamedAdminAuthoritiesMapper();

	/**
	 * @param authoritiesMapper
	 */
	public void setAuthoritiesMapper(OIDCAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.authentication.AuthenticationProvider#
	 * authenticate(org.springframework.security.core.Authentication)
	 */
	@Override
	public Authentication authenticate(final Authentication authentication) throws AuthenticationException {

		if (!supports(authentication.getClass())) {
			return null;
		}

		if (authentication instanceof PendingOIDCAuthenticationToken) {

			PendingOIDCAuthenticationToken token = (PendingOIDCAuthenticationToken) authentication;

			// get the ID Token value out
			JWT idToken = token.getIdToken();

			// load the user info if we can
//			UserInfo userInfo = userInfoFetcher.loadUserInfo(token);
			 UserInfo userInfo = null;
//userInfo.setAddress(address);
			
			if (userInfo == null) {
				// user info not found -- could be an error, could be fine
			} else {
				// if we found userinfo, double check it
				if (!Strings.isNullOrEmpty(userInfo.getSub()) && !userInfo.getSub().equals(token.getSub())) {
					// the userinfo came back and the user_id fields don't match what was in the id_token
					throw new UsernameNotFoundException("user_id mismatch between id_token and user_info call: " + token.getSub() + " / " + userInfo.getSub());
				}
			}

			return createAuthenticationToken(token, authoritiesMapper.mapAuthorities(idToken, userInfo), userInfo);
		}

		return null;
	}

}
