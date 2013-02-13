security-eval
=============

Project to experiment with security in JBoss with picketlink.

What's In This Demo?
--------------------

This is a demonstration/evaluation of security configurations using
picketlink 2.1.6.Final in JBoss 7.1.1.Final.

The following WARs are included in this eval:

* security-eval-idp:  A SAML Identity Provider
* security-eval-jaxrs:  A simple REST service @ /greeting
* security-eval-webapp-1: A web application that participates in SAML SSO with the IDP.  Also uses an *impersonation* technique to make authenticated calls to the REST service above.
* security-eval-webapp-2: A web application that participates in SAML SSO with the IDP.
* security-eval-webapp-3: A web application that participates in SAML SSO with the IDP.  Also uses a *shared token* technique to make authenticated calls to the REST service above.

How Do I Run It?
----------------

I couldn't be simpler.  Clone this repository, then do:

    $ mvn clean install

The result will be a fully configured instance of JBoss AS 7.1.1.Final located here:

    security-eval-installer/target/jboss-as-7.1.1.Final

Simply start JBoss:

    $ ./security-eval-installer/target/jboss-as-7.1.1.Final/bin/standalone.sh

Once it's up, you can hit the following URLs:

* http://localhost:8080/security-eval-jaxrs/greeting
* http://localhost:8080/security-eval-webapp-1/
* http://localhost:8080/security-eval-webapp-2/
* http://localhost:8080/security-eval-webapp-3/

For all of the above endpoints, you can log in using any of the following users:

* eric
* gary
* kurt
* kevin
* jeff

Use the password:

    password

