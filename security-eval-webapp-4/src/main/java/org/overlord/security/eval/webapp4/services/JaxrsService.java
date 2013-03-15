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
package org.overlord.security.eval.webapp4.services;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Set;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.HttpContext;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;
import org.jboss.security.SecurityContextAssociation;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLAssertionWriter;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

/**
 * @author eric.wittmann@redhat.com
 */
public class JaxrsService {

    private static final String ENDPOINT = "http://localhost:8080/security-eval-jaxrs/greeting";

    private HttpServletRequest context;

    /**
     * Constructor.
     */
    public JaxrsService(HttpServletRequest context) {
        this.context = context;
    }

    /**
     * @return
     */
    public String doGreeting() {
        try {
            ClientRequest request = new ClientRequest(ENDPOINT, getSamlAssertionExecutor());
            ClientResponse<String> response = request.get(String.class);
            int status = response.getStatus();
            if (status == 401) {
                throw new Exception("Not Authorized to call '" + ENDPOINT + "'.");
            }
            System.out.println("Greeting (web-app-4) status: " + status);
            return response.getEntity();
        } catch (Throwable e) {
            return "FAIL: " + e.getMessage();
        }

    }

    /**
     * @return
     */
    private ClientExecutor getSamlAssertionExecutor() {
        try {
            final String b64Assertion = createB64Assertion(this.context.getUserPrincipal());

            DefaultHttpClient httpClient = new DefaultHttpClient();
            httpClient.addRequestInterceptor(new HttpRequestInterceptor() {
                @Override
                public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
                    System.out.println("Setting HTTP Authorization to: " + b64Assertion);
                    request.setHeader("Authorization", "Basic " + b64Assertion);
                }
            });
            ClientExecutor clientExecutor = new ApacheHttpClient4Executor(httpClient);
            return clientExecutor;
        } catch (Throwable e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * @param principal
     * @return
     * @throws Exception
     * @throws FactoryConfigurationError
     * @throws XMLStreamException
     * @throws ProcessingException
     * @throws UnsupportedEncodingException
     */
    protected static String createB64Assertion(final Principal principal) throws Exception,
            FactoryConfigurationError, XMLStreamException, ProcessingException, UnsupportedEncodingException {
        NameIDType issuer = SAMLAssertionFactory.createNameID(null, null, "/security-eval-webapp-4");
        SubjectType subject = AssertionUtil.createAssertionSubject(principal.getName());
        AssertionType assertion = AssertionUtil.createAssertion(UUID.randomUUID().toString(), issuer);
        assertion.setSubject(subject);
        AssertionUtil.createTimedConditions(assertion, 10000);
        ConditionAbstractType restriction = SAMLAssertionFactory.createAudienceRestriction("/security-eval-jaxrs");
        assertion.getConditions().addCondition(restriction);
        addRoleStatements(assertion, principal);

        // Serialize the Assertion
        XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write("SAML-BEARER-TOKEN:".getBytes("UTF-8"));
        XMLStreamWriter xmlStreamWriter = xmlOutputFactory.createXMLStreamWriter(baos);
        SAMLAssertionWriter writer = new SAMLAssertionWriter(xmlStreamWriter);
        writer.write(assertion);
        xmlStreamWriter.flush();
        xmlStreamWriter.close();
        String b64Assertion = new String(Base64.encodeBase64(baos.toByteArray()), "UTF-8");
        return b64Assertion;
    }

    /**
     * Adds the roles to the assertion as attribute statements.
     * @param assertion
     * @param principal
     */
    private static void addRoleStatements(AssertionType assertion, Principal principal) {
        AttributeType attribute = new AttributeType("Role");
        ASTChoiceType attributeAST = new ASTChoiceType(attribute);
        AttributeStatementType roleStatement = new AttributeStatementType();
        roleStatement.addAttribute(attributeAST);

        Set<Principal> userRoles = SecurityContextAssociation.getSecurityContext().getAuthorizationManager().getUserRoles(principal);
        if (userRoles != null) {
            for (Principal role : userRoles) {
                attribute.addAttributeValue(role.getName());
            }
        }

        assertion.addStatement(roleStatement);
    }

}
