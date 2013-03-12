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
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
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
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLAssertionWriter;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;

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
            final String currentUser = this.context.getRemoteUser();
            final String b64Assertion = createB64Assertion(currentUser);

            DefaultHttpClient httpClient = new DefaultHttpClient();
            httpClient.addRequestInterceptor(new HttpRequestInterceptor() {
                @Override
                public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
                    System.out.println("Setting HTTP Authorization to: " + b64Assertion);
                    request.setHeader("Authorization", b64Assertion);
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
     * @param currentUser
     * @return
     * @throws Exception
     * @throws FactoryConfigurationError
     * @throws XMLStreamException
     * @throws ProcessingException
     * @throws UnsupportedEncodingException
     */
    protected static String createB64Assertion(final String currentUser) throws Exception,
            FactoryConfigurationError, XMLStreamException, ProcessingException, UnsupportedEncodingException {
        DatatypeFactory dtFactory = getDatatypeFactory();
        GregorianCalendar now = new GregorianCalendar();
        GregorianCalendar then = new GregorianCalendar();
        then.add(Calendar.SECOND, 10);
        NameIDType subjectNameId = SAMLAssertionFactory.createNameID("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", null, currentUser);
        ConditionAbstractType restriction = SAMLAssertionFactory.createAudienceRestriction("/security-eval-jaxrs/");
        SubjectConfirmationType subjectConfirmation = SAMLAssertionFactory.createSubjectConfirmation(null, SAMLUtil.SAML2_SENDER_VOUCHES_URI, null);
        List<StatementAbstractType> statements = null;
        XMLGregorianCalendar xmlNow = dtFactory.newXMLGregorianCalendar(now);
        XMLGregorianCalendar xmlThen = dtFactory.newXMLGregorianCalendar(now);
        AssertionType assertion = SAMLAssertionFactory.createAssertion(
                UUID.randomUUID().toString(),
                SAMLAssertionFactory.createNameID(null, null, "/security-eval-webapp-4/"),
                dtFactory.newXMLGregorianCalendar(now),
                SAMLAssertionFactory.createConditions(xmlNow, xmlThen, restriction),
                SAMLAssertionFactory.createSubject(subjectNameId, subjectConfirmation),
                statements);

        // Serialize the Assertion
        XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = xmlOutputFactory.createXMLStreamWriter(baos);
        SAMLAssertionWriter writer = new SAMLAssertionWriter(xmlStreamWriter);
        writer.write(assertion);
        xmlStreamWriter.flush();
        xmlStreamWriter.close();
        String b64Assertion = new String(Base64.encodeBase64(baos.toByteArray()), "UTF-8");
        return b64Assertion;
    }

    /**
     * @return
     * @throws Exception
     */
    private static DatatypeFactory getDatatypeFactory() throws Exception {
        return DatatypeFactory.newInstance();
    }

    public static void main(String [] args) throws Exception {
        DatatypeFactory dtFactory = getDatatypeFactory();
        System.out.println("DTFactory: " + dtFactory.getClass());
        XMLGregorianCalendar xmlNow = dtFactory.newXMLGregorianCalendar(new GregorianCalendar());
        System.out.println(xmlNow.toString());
        createB64Assertion("eric");
    }

}