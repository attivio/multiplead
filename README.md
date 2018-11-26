# multiplead
Authentication Provider for multiple AD configurations

By default in the platform, an AD Authentication Provider takes a single AD config and leverages that config to authenticate users. Occassionally, there may be separate AD deployments that need to be checked against. For example, Attivio maintains 2 ADs, 1 for internal accounts, and another for external accounts.

This eModule extends the AD AuthenticationProvider to take a list of AD Configs (beans), and checks each of them until a user is authenticated. 

To use, update your project's configuration.xml file to have a default authentication provider: 

```xml
<default-authentication-provider authentication-provider-ref="defaultMultipleAuthenticationProvider"/>
```

Then, create your bean for the `defaultMultipleAuthenticationProvider` defined above. Here is an example with 3 AD configs, for different geographic regions:

```xml
<beans xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.springframework.org/schema/beans" xmlns:util="http://www.springframework.org/schema/util" xmlns:sec="http://www.springframework.org/schema/security" xsi:schemaLocation=" http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security-4.1.xsd">
  <bean name="defaultMultipleAuthenticationProvider" class="com.attivio.securityad.multiplead.ActiveDirectoryAuthenticationProvider">
    <property name="adConfigs">
      <list>
        <ref bean="activeDirectoryConfig"/>
        <ref bean="activeDirectoryConfigEurope"/>
        <ref bean="activeDirectoryConfigApac" />
      </list>
    </property>
  </bean>
</beans>
```

Assuming you have defined your AD configs for the above regions defined, you will now be able to authenticate users that exist in any of the above AD instances. 

For help on creating AD config beans, see: https://answers.attivio.com/display/extranet55/Active+Directory+and+LDAP+Configuration
