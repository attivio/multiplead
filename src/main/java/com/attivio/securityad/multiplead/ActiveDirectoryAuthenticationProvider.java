/**
 * Copyright 2015 Attivio Inc., All rights reserved.
 */
package com.attivio.securityad.multiplead;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.security.auth.login.LoginException;

import com.attivio.sdk.AttivioException;
import com.attivio.sdk.error.SecurityError;
import com.attivio.sdk.security.AttivioPrincipal;
import com.attivio.sdk.security.AttivioPrincipal.PrincipalType;
import com.attivio.sdk.security.AttivioRole;
import com.attivio.sdk.security.SecurityUtils;
import com.attivio.security.authentication.AuthenticationProvider;
import com.attivio.security.authentication.AuthenticationProviderUtils;
import com.attivio.securityad.AbstractDirectoryConfig.DirectorySchemaInfo;
import com.attivio.securityad.ActiveDirectoryConfig;
import com.attivio.securityad.principal.DirectoryUtils;
import com.attivio.util.AttivioLogger;

/**
 * <code>ActiveDirectoryAuthenticationProvider</code> is a {@link AuthenticationProvider} that authenticates against an Active Directory Server.
 * 
 * 
 */
public class ActiveDirectoryAuthenticationProvider implements AuthenticationProvider {

	private final AttivioLogger log = AttivioLogger.getLogger(ActiveDirectoryAuthenticationProvider.class);
	private static final String MEMBER_OF = "memberOf";
	private static final String[] attrIdsToSearch = new String[] { MEMBER_OF };
	private static final String SEARCH_BY_SAM_ACCOUNT_NAME = "(sAMAccountName=%s)";

	private List<ActiveDirectoryConfig> adConfigs = null;

	public List<ActiveDirectoryConfig> getAdConfigs() {
		return adConfigs;
	}

	public void setAdConfigs(List<ActiveDirectoryConfig> adConfigs) {
		this.adConfigs = adConfigs;
	}

	@Override
	public AttivioPrincipal authenticate(String username, String password) throws AttivioException {
		if (adConfigs == null || adConfigs.isEmpty()) {
			throw new AttivioException(SecurityError.INVALID_CONFIGURATION, "Active Directory Configuration not set");
		}

		AttivioException attivioException = null;

		for (ActiveDirectoryConfig adConfig : adConfigs) {

			SearchResult sr = null;
			LdapContext ctx = null;
			try {
				sr = findUser(adConfig, username);
				String userDn = sr.getNameInNamespace();
				ctx = adConfig.createContext(userDn, password);
				AttivioPrincipal ap = new AttivioPrincipal(adConfig.getRealmId(), getSid(adConfig, sr), username, PrincipalType.USER);
				Set<AttivioRole> roles = getUserRolesByDn(adConfig, ctx, userDn);
				roles.addAll(getUserRolesByQuery(adConfig, username));
				ap.setRoles(roles);
				if (log.isTraceEnabled()) {
					AuthenticationProviderUtils.logAuthSuccess(log, ap);
				}      
				return ap;
			} catch (LoginException e) {
				log.debug(e, "Failed to authenticate using : %s", adConfig.getUrl());
				attivioException = new AttivioException(SecurityError.AUTH_FAILED, e, "Failed to authenticate");
			} catch (NamingException e) {
				log.debug(e, "Failed to authenticate using : %s", adConfig.getUrl());
				attivioException = new AttivioException(SecurityError.AUTH_FAILED, e, "Failed to authenticate");
			} finally {
				close(ctx);
			}
		}

		if (attivioException != null) {
			throw attivioException;
		} else {
			throw new AttivioException(SecurityError.AUTH_FAILED, "Failed to authenticate - Reason Unknown");
		}
	}

	private SearchResult findUser(ActiveDirectoryConfig adConfig, String username) throws NamingException, LoginException, AttivioException {
		LdapContext ctx = null;
		try {
			ctx = adConfig.createContext();

			SearchControls ctls = new SearchControls();
			ctls.setCountLimit(1);
			ctls.setDerefLinkFlag(true);
			ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

			String filter = DirectoryUtils.getANDFilter(
					adConfig.getUserSearchFilter(),
					DirectoryUtils.getObjectClassFilter(adConfig.getSchema().getUserObjectClass()),
					DirectoryUtils.getBasicFilter(adConfig.getSchema().getUsernameAddr(), username)
					);

			if (log.isDebugEnabled()) {
				log.debug("Searching for users with filter: \'" + filter + "\'" + " from base dn: " + adConfig.getUserSearchBase());
			}

			NamingEnumeration<?> results = ctx.search(adConfig.getUserSearchBase(), filter, ctls);
			try {
				final boolean foundUser = results.hasMoreElements();
				log.trace("Found user?: " + foundUser);

				if (!foundUser) {
					throw new LoginException("Invalid Username");
				}

				return (SearchResult) results.nextElement();
			} finally {
				results.close();
			}
		} finally {
			close(ctx);
		}
	}

	private void close(LdapContext ctx) {
		if (ctx != null) {
			try {
				ctx.close();
			} catch (NamingException e) {
				log.error(SecurityError.COMMUNICATION_ERROR, e, "Failed to close connection");
			}
		}
	}

	private void close(InitialDirContext ctx) {
		if (ctx != null) {
			try {
				ctx.close();
			} catch (NamingException e) {
				log.error(SecurityError.COMMUNICATION_ERROR, e, "Failed to close connection");
			}
		}
	}

	private Set<AttivioRole> getUserRolesByDn(ActiveDirectoryConfig adConfig, LdapContext ctx, String userDn) throws LoginException, NamingException {
		Set<AttivioRole> roleList = new HashSet<AttivioRole>();
		DirectorySchemaInfo schema = adConfig.getSchema();

		SearchControls ctls = new SearchControls();
		ctls.setDerefLinkFlag(true);
		ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		Set<String> dnProcessed = new HashSet<String>();
		Set<String> dn2process = new HashSet<String>();
		dn2process.add(userDn);

		while (dn2process.size() > 0) {
			Set<String> processing = new HashSet<String>(dn2process);
			dn2process.clear();

			for (String dn : processing) {
				dnProcessed.add(dn);

				String filter = DirectoryUtils.getANDFilter(
						adConfig.getGroupSearchFilter(),
						DirectoryUtils.getObjectClassFilter(adConfig.getSchema().getGroupObjectClass()),
						DirectoryUtils.getBasicFilter(adConfig.getSchema().getGroupMembershipAddr(), dn)
						);

				NamingEnumeration<?> results = ctx.search(adConfig.getUserSearchBase(), filter, ctls);

				while (results.hasMoreElements()) {
					SearchResult result = (SearchResult) results.nextElement();

					String nextDn = result.getNameInNamespace();
					if (!dnProcessed.contains(nextDn)) {
						dn2process.add(nextDn);
					}

					Attributes attributes = result.getAttributes();
					if (attributes == null) {
						continue;
					}

					Attribute roleAttribute = attributes.get(schema.getGroupNameAddr());
					if (roleAttribute == null) {
						continue;
					}

					AttivioRole role = new AttivioRole(roleAttribute.get().toString());
					roleList.add(role);
				}
			}
		}

		if (log.isDebugEnabled()) {
			log.debug("Found user roles: %s %s", userDn, roleList);
		}

		return roleList;
	}

	private Set<AttivioRole> getUserRolesByQuery (ActiveDirectoryConfig adConfig, String user) {
		Set<AttivioRole> roleList = new HashSet<AttivioRole>();
		Hashtable<String, String> env = new Hashtable<String, String>();

		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, adConfig.getUrl());
		env.put(Context.SECURITY_PRINCIPAL, adConfig.getBindDn());
		env.put(Context.SECURITY_CREDENTIALS, adConfig.getBindPassword());

		InitialDirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
			String filter = String.format(SEARCH_BY_SAM_ACCOUNT_NAME, user);
			SearchControls constraints = new SearchControls();
			constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
			constraints.setReturningAttributes(attrIdsToSearch);
			NamingEnumeration<?> results = ctx.search(adConfig.getUserSearchBase(), filter, constraints);
			// Fail if no entries found
			if (results == null || !results.hasMore()) {
				return roleList;
			}
			// Get result for the first entry found
			SearchResult result = (SearchResult) results.next();
			// Get the entry's attributes
			Attributes attrs = result.getAttributes();
			Attribute attr = attrs.get(attrIdsToSearch[0]);

			NamingEnumeration<?> e = attr.getAll();
			while (e.hasMore()) {
				String value = (String) e.next();
				AttivioRole role = new AttivioRole(value.substring(3, value.indexOf(",")));
				roleList.add(role);
			}
		} catch (Exception e) {
			log.warn(SecurityError.ERROR, e, "Error while querying user roles for %s", user);
		} finally {
			close(ctx);
		}
		return roleList;
	}

	private String getSid(ActiveDirectoryConfig adConfig, SearchResult searchResult) {
		try {
			Attributes attributes = searchResult.getAttributes();
			Attribute sidAttr = attributes.get(adConfig.getSchema().getSidAddr());
			if (sidAttr != null) {
				Object sid = sidAttr.get();
				if (sid instanceof byte[])
					return SecurityUtils.getSidString((byte[]) sid);
				else
					log.error(SecurityError.USER_DIRECTORY_ERROR, "Unsupported SID type: " + sid.getClass().getCanonicalName());
			} else {
				log.error(SecurityError.USER_DIRECTORY_ERROR, "Could not determine SID because attribute '" + adConfig.getSchema().getSidAddr() + "' was not found");
			}
		} catch (NamingException e) {
			log.error(SecurityError.USER_DIRECTORY_ERROR, e.toString());
		}
		return null;
	}
}