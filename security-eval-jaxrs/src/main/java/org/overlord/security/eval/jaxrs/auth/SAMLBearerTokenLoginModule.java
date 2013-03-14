/*
 * Copyright 2013 JBoss Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.overlord.security.eval.jaxrs.auth;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.picketlink.identity.federation.core.parsers.saml.SAMLAssertionParser;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

/**
 * @author eric.wittmann@redhat.com
 */
public class SAMLBearerTokenLoginModule extends AbstractServerLoginModule {

    /** Configured in standalone.xml in the login module */
    private String expectedIssuer;

    private Principal identity;
    private Set<String> roles = new HashSet<String>();

    /**
     * Constructor.
     */
    public SAMLBearerTokenLoginModule() {
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        expectedIssuer = (String) options.get("expectedIssuer");
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        System.out.println("LOGIN called: " + getClass().getSimpleName());
        InputStream is = null;
        try {
            HttpServletRequest request =
                    (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
            System.out.println("Request: " + request);
            String authorization = request.getHeader("Authorization");
            System.out.println("Authorization Header: " + authorization);
            if (authorization != null && authorization.startsWith("Basic")) {
                String b64Data = authorization.substring(6);
                byte[] dataBytes = Base64.decodeBase64(b64Data);
                String data = new String(dataBytes, "UTF-8");
                System.out.println("DATA: " + data);
                if (data.startsWith("SAML-BEARER-TOKEN:")) {
                    String assertionData = data.substring(18);
                    System.out.println("Assertion DATA: " + assertionData);
                    SAMLAssertionParser parser = new SAMLAssertionParser();
                    is = new ByteArrayInputStream(assertionData.getBytes("UTF-8"));
                    XMLEventReader xmlEventReader = XMLInputFactory.newInstance().createXMLEventReader(is);
                    Object parsed = parser.parse(xmlEventReader);
                    System.out.println("Parsed Object: " + parsed.getClass());
                    AssertionType assertion = (AssertionType) parsed;
                    if (validateAssertion(assertion, request) && consumeAssertion(assertion)) {
                        System.out.println("SAML assertion login passed, setting loginOk = true");
                        loginOk = true;
                        return true;
                    }
                }
            }
        } catch (LoginException le) {
            throw le;
        } catch (Exception e) {
            e.printStackTrace();
            loginOk = false;
            return false;
        } finally {
            IOUtils.closeQuietly(is);
        }
        return super.login();
    }

    /**
     * Validates that the assertion is acceptable based on configurable criteria.
     * @param assertion
     * @param request
     * @throws LoginException
     */
    private boolean validateAssertion(AssertionType assertion, HttpServletRequest request) throws LoginException {
        // Possibly fail the assertion based on issuer.
        String issuer = assertion.getIssuer().getValue();
        if (!issuer.equals(expectedIssuer)) {
            throw new LoginException("Unexpected SAML Assertion Issuer: " + issuer);
        }

        // Possibly fail the assertion based on audience restriction
        String currentAudience = request.getContextPath();
        Set<String> audienceRestrictions = getAudienceRestrictions(assertion);
        if (!audienceRestrictions.contains(currentAudience)) {
            throw new LoginException("SAML Assertion Audience Restrictions not valid for this context ("
                    + currentAudience + ")");
        }

        // Possibly fail the assertion based on time.
        Date now = new Date();
        ConditionsType conditions = assertion.getConditions();
        Date notBefore = conditions.getNotBefore().toGregorianCalendar().getTime();
        Date notOnOrAfter = conditions.getNotOnOrAfter().toGregorianCalendar().getTime();
        if (now.compareTo(notBefore) == -1) {
            throw new LoginException("SAML Assertion not yet valid.");
        }
        if (now.compareTo(notOnOrAfter) >= 0) {
            throw new LoginException("SAML Assertion no longer valid.");
        }

        return true;
    }

    /**
     * Gets the audience restriction condition.
     * @param assertion
     */
    private Set<String> getAudienceRestrictions(AssertionType assertion) {
        Set<String> rval = new HashSet<String>();
        if (assertion == null || assertion.getConditions() == null || assertion.getConditions().getConditions() == null)
            return rval;

        List<ConditionAbstractType> conditions = assertion.getConditions().getConditions();
        for (ConditionAbstractType conditionAbstractType : conditions) {
            if (conditionAbstractType instanceof AudienceRestrictionType) {
                AudienceRestrictionType art = (AudienceRestrictionType) conditionAbstractType;
                List<URI> audiences = art.getAudience();
                for (URI uri : audiences) {
                    rval.add(uri.toString());
                    System.out.println("**** Found SAML Audience restriction: " + uri.toString());
                }
            }
        }

        return rval;
    }

    /**
     * Consumes the assertion, resulting in the extraction of the Subject as the
     * JAAS principal and the Role Statements as the JAAS roles.
     * @param assertion
     * @throws Exception
     */
    private boolean consumeAssertion(AssertionType assertion) throws Exception {
        System.out.println("Consuming SAML assertion");
        SubjectType samlSubjectType = assertion.getSubject();
        String samlSubject = ((NameIDType) samlSubjectType.getSubType().getBaseID()).getValue();
        System.out.println("Subject: " + samlSubject);
        identity = createIdentity(samlSubject);

        Set<StatementAbstractType> statements = assertion.getStatements();
        System.out.println("Consuming SAML assertion statements");
        for (StatementAbstractType statement : statements) {
            if (statement instanceof AttributeStatementType) {
                AttributeStatementType attrStatement = (AttributeStatementType) statement;
                List<ASTChoiceType> attributes = attrStatement.getAttributes();
                for (ASTChoiceType astChoiceType : attributes) {
                    if (astChoiceType.getAttribute() != null && astChoiceType.getAttribute().getName().equals("Role")) {
                        List<Object> values = astChoiceType.getAttribute().getAttributeValue();
                        for (Object roleValue : values) {
                            if (roleValue != null) {
                                roles.add(roleValue.toString());
                                System.out.println("Found SAML Role Attribute: " + roleValue.toString());
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getIdentity()
     */
    @Override
    protected Principal getIdentity() {
        return identity;
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getRoleSets()
     */
    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group[] groups = new Group[1];
        groups[0] = new SimpleGroup("Roles");
        try {
            for (String role : roles) {
                groups[0].addMember(createIdentity(role));
            }
        } catch (Exception e) {
            throw new LoginException("Failed to create group principal: " + e.getMessage());
        }
        return groups;
    }

}
