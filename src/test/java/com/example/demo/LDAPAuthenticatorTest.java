package com.example.demo;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.naming.AuthenticationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP", address = "localhost", port = 10390)})
@CreateDS(
		allowAnonAccess = false, partitions = {@CreatePartition(name = "TestPartition", suffix = "dc=plug,dc=com")})
@ApplyLdifFiles({"users.ldif"})
@ExtendWith(MockitoExtension.class)
public class LDAPAuthenticatorTest extends AbstractLdapTestUnit
{


	private LdapTemplate ldapTemplate;

	@Test
	public void givenValidPrincipalAndCredentials_whenAuthenticateUser_thenReturnTrue() throws NamingException
	{
		LDAPAuthenticator ldapAuthenticator = new LDAPAuthenticator("localhost", "10390", "cn=Admin,ou=Users,dc=plug,dc=com", "1234567");
		Authentication authenticated = ldapAuthenticator.authenticate(
				new UsernamePasswordAuthenticationToken("cn=Pepe Pompin,ou=Users,dc=plug,dc=com", "12345"));
		assertNotNull(authenticated);
		assertTrue(authenticated.getAuthorities().contains(new SimpleGrantedAuthority("Operations")));
		assertTrue(authenticated.getAuthorities().contains(new SimpleGrantedAuthority("Users")));
		assertEquals(2, authenticated.getAuthorities().size());
	}

	@Test(expected = AuthenticationException.class)
	public void givenValidPrincipalAndInvalidCredentials_whenAuthenticateUser_thenShouldThrowException() throws NamingException
	{
		LDAPAuthenticator ldapAuthenticator = new LDAPAuthenticator("localhost", "10390", "cn=Admin,ou=Users,dc=plug,dc=com", "1234567");
		ldapAuthenticator.authenticate(
				new UsernamePasswordAuthenticationToken("cn=Pepe Pompin,ou=Users,dc=plug,dc=com", "678910"));

	}

	@Test(expected = AuthenticationException.class)
	public void givenInvalidPrincipal_whenAuthenticateUser_thenShouldThrowException() throws NamingException
	{
		LDAPAuthenticator ldapAuthenticator = new LDAPAuthenticator("localhost", "10390", "cn=Admin,ou=Users,dc=plug,dc=com", "1234567");
		ldapAuthenticator.authenticate(new UsernamePasswordAuthenticationToken("cn=Pipi Pompin,ou=Users,dc=plug,dc=com", "12345"));
	}


}
