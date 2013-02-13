<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@page import="org.overlord.security.eval.webapp3.services.JaxrsService"%>
<%
  JaxrsService svc = new JaxrsService(request);
%>
<html>
<head>
<title>Web Application 1</title>
</head>
<body>
<h3>Welcome to Web Application 1, <%= request.getRemoteUser() %>!</h3>
<p>
  The secure JAX-RS Greeting service says:  "<%= svc.doGreeting() %>"
</p>
<p>
  Wondering what's going on in this demo?  This page is a JSP that's 
  generating two messages.  The first, in the H3 tag above, is a
  simple call to <code>request.getRemoteUser()</code>.
</p>
<p>
  The second message (below it) is the response from making a JAX-RS
  REST call from the server-side JSP to another web application (WAR)
  deployed in JBoss.  This hopefully shows that the username found in
  message one in the H3 (the user currently logged in to this web
  application) is the <b>same</b> as the username detected by the 
  JAX-RS service.  This indicates that this web application is able
  to execute REST calls on behalf of the currently logged-in user!
</p>
<p>
  Note: this is similar to security-eval-webapp-1 except that this version
  does *not* use impersonation.
</p>
<br/>
<br/>
<p>
  Want to test Global Logout?  <a href="?GLO=true">Click Here!</a>
</p>
</body>
</html>
