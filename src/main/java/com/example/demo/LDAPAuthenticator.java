package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.stream.Collectors;

import static java.lang.String.format;

@Component
public class LDAPAuthenticator
{

	private static final String ldapFormatUrl = "ldap://%s:%s";
	private static final String authenticationType = "simple";

	private String ldapUrl;
	private String ldapPort;
	private String ldapUsername;
	private String ldapPassword;
	private String ldapSearchPrefix;
	private String ldapSearchSuffix;

	public LDAPAuthenticator(
			@Value("${ldap.url:localhost}") String ldapUrl,
			@Value("${ldap.port:10390}") String ldapPort,
			@Value("${ldap.username:Admin}") String ldapUsername,
			@Value("${ldap.password:1234567}") String ldapPassword,
			@Value("${ldap.search.prefix:cn=}") String ldapSearchPrefix,
			@Value("${ldap.search.suffix:,ou=Users,dc=plug,dc=com}") String ldapSearchSuffix)
	{
		this.ldapUrl          = ldapUrl;
		this.ldapPort         = ldapPort;
		this.ldapUsername     = ldapUsername;
		this.ldapPassword     = ldapPassword;
		this.ldapSearchPrefix = ldapSearchPrefix;
		this.ldapSearchSuffix = ldapSearchSuffix;

	}

	private static final String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

	public Authentication authenticate(Authentication authentication) throws NamingException
	{
		String principal = format("%s%s%s", ldapSearchPrefix, authentication.getName(), ldapSearchSuffix);
		String credentials = authentication.getCredentials().toString();

		Hashtable<String, String> environment = generateEnvironment();

		DirContext context = new InitialDirContext(environment);

		String filter = generateFilter(credentials);
		SearchControls searchControls = generateSearchControls();
		List<GrantedAuthority> authorities = searchForAuthorities( context,  principal, filter , searchControls );
		context.close();
		return new UsernamePasswordAuthenticationToken(principal, credentials, authorities);

	}

	private SearchControls generateSearchControls(){
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchControls.setReturningAttributes(new String[] { "ou" });
		return searchControls;
	}

	private Hashtable<String, String> generateEnvironment(){
		Hashtable<String, String> environment = new Hashtable<>();
		environment.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
		environment.put(Context.PROVIDER_URL, format(ldapFormatUrl, ldapUrl, ldapPort));
		environment.put(Context.SECURITY_AUTHENTICATION, authenticationType);
		environment.put(Context.SECURITY_PRINCIPAL, ldapUsername);
		environment.put(Context.SECURITY_CREDENTIALS, ldapPassword);
		return environment;
	}

	private String generateFilter(String credentials){
		return format("(&(userPassword=%s))", credentials);
	}

	private NamingEnumeration<SearchResult> searchForUserGroups(DirContext context, String principal, String filter, SearchControls searchControls) throws NamingException
	{
		NamingEnumeration<SearchResult> searchResults;
		try
		{
			searchResults = context.search(principal, filter, searchControls);
		}
		catch (NamingException exception)
		{
			throw new AuthenticationException();
		}
		if (!searchResults.hasMoreElements())
		{
			throw new AuthenticationException();
		}
		return searchResults;
	}

	private List<GrantedAuthority> searchForAuthorities(DirContext context, String principal, String filter, SearchControls searchControls) throws NamingException
	{
		NamingEnumeration<SearchResult> searchResults = searchForUserGroups(context, principal, filter, searchControls);
		SearchResult entry = searchResults.next();
		Attributes attrs = entry.getAttributes();
		Attribute ous = attrs.get("ou");
		return new ArrayList<>(Collections.list(ous.getAll()).stream().map(Object::toString).map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
	}
}

