<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@page import="org.overlord.security.eval.webapp1.services.JaxrsService"%>
<%
  JaxrsService svc = new JaxrsService();
%>
<html>
<head>
<title>Web Application 1</title>
</head>
<body>
<h3>Welcome to Web Application 1, <%= request.getRemoteUser() %>!</h3>
<p>
  The Greeting service says:  <%= svc.doGreeting() %>
</p>
</body>
</html>
