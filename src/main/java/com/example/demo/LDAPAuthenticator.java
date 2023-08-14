package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

import org.springframework.security.core.Authentication;

import static java.lang.String.format;

@Component
public class LDAPAuthenticator
{

	private static final String ldapFormatUrl = "ldap://%s:%s";
	private static final String ouFormatFilter = "(&(ou=%s))";
	private static final String authenticationType = "simple";

	private String ldapUrl;
	private String ldapPort;
	private String ldapUsername;
	private String ldapPassword;

	public LDAPAuthenticator(
			@Value("${ldap.url:localhost}") String ldapUrl,
			@Value("${ldap.port:10390}") String ldapPort,
			@Value("${ldap.username:Admin}") String ldapUsername,
			@Value("${ldap.password:1234567}") String ldapPassword){
		this.ldapUrl = ldapUrl;
		this.ldapPort = ldapPort;
		this.ldapUsername = ldapUsername;
		this.ldapPassword = ldapPassword;

	}
	private static final String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";
	public Authentication authenticate(Authentication authentication) throws NamingException
	{
		String principal = authentication.getName();
		String credentials = authentication.getCredentials().toString();

		Hashtable<String, String> environment = new Hashtable<>();
		environment.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
		environment.put(Context.PROVIDER_URL, format(ldapFormatUrl, ldapUrl, ldapPort));
		environment.put(Context.SECURITY_AUTHENTICATION, authenticationType);
		environment.put(Context.SECURITY_PRINCIPAL, ldapUsername);
		environment.put(Context.SECURITY_CREDENTIALS, ldapPassword);

		DirContext context = new InitialDirContext(environment);

		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchControls.setReturningAttributes(new String[] { "ou" });

		String filter = format("(&(userPassword=%s))", credentials);

		List<String> userGroups = new ArrayList<>();
		NamingEnumeration<SearchResult> searchResults;
		try{
			searchResults = context.search(principal, filter, searchControls);
		}
		catch(NamingException exception){
			throw new AuthenticationException();
		}
		if(!searchResults.hasMoreElements()){
			throw new AuthenticationException();
		}

		SearchResult entry = searchResults.next();
		Attributes attrs = entry.getAttributes();
		Attribute ous = attrs.get("ou");
		for(Object attribute : Collections.list(ous.getAll())){
			userGroups.add(attribute.toString());
		}
		context.close();
		List<GrantedAuthority> authorities = new ArrayList<>();
		for(String userGroup : userGroups){
			authorities.add(new SimpleGrantedAuthority(userGroup));
		}
		return new UsernamePasswordAuthenticationToken(principal, credentials, authorities);


	}




}

