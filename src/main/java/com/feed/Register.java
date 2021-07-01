package com.feed;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONException;
import org.json.JSONObject;

import com.google.appengine.api.urlfetch.FetchOptions;
import com.google.appengine.api.urlfetch.HTTPHeader;
import com.google.appengine.api.urlfetch.HTTPMethod;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.appengine.api.urlfetch.URLFetchServiceFactory;
import com.google.appengine.repackaged.org.joda.time.DateTime;


@WebServlet("/register")
public class Register extends HttpServlet {
	private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger("logger");	

    public Register() {
        super();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        HttpSession session=request.getSession(false);  

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Allow-Headers", "*");

		if(session==null || session.getAttribute("userId")==null) {
      			request.getRequestDispatcher("/jsp/register.jsp").forward(request,response);

		}
		else
		{
      			response.sendRedirect("/");

		}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setHeader("Access-Control-Allow-Origin", "https://malkarajtraining12.uc.r.appspot.com/");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Allow-Headers", "*");
		HMACAlgorithm hash=new HMACAlgorithm();

        SyncApp sync=new SyncApp();
        
	    StringBuffer jb = new StringBuffer();
	    PrintWriter out=response.getWriter();
	    String line = null;
	    BufferedReader reader = request.getReader();
	    while ((line = reader.readLine()) != null)
	        jb.append(line);
	    String str=jb.toString();
        JSONObject json=new JSONObject(str.toString());
        UserDao userOp=new UserOperations();
        CredentialValidator v=new CredentialValidator();
        response.setContentType("application/json");

        User user=new User();
        try {
        	
	        	String Origin = request.getHeader("Origin");
		    	String email=json.get("email").toString();
				String pass=BCrypt.hashpw(json.get("password").toString(),BCrypt.gensalt(10));
				String inboundAppId=request.getHeader("X-Appengine-Inbound-Appid");
		    	UUID id=UUID.randomUUID();
		    	System.out.println(Origin);
		        if(v.isValidateCredentials(email))
		        {
			        DateTime now = new DateTime();
			        Date date=new Date(now.getMillis());
					user.setEmail(email);
					user.setPassword(pass);
					user.setDate(date);
					user.setImage("null.png");
					user.setActive(true);
		        }
		        else
		        {
		            JSONObject obj=new JSONObject();
		            response.setStatus(400);
		            obj.put("success", false);
		            obj.put("code", 400);
		            obj.put("message", "Invalid email id");
		            out.println(obj);
	
		        }
		        
	        
	        
				JSONObject resp=new JSONObject();
				
				if(inboundAppId!=null && inboundAppId.equals("malkarajtraining12")) 
				{
					
					String token=request.getHeader("Authorization");
					if(token.equals(hash.calculateHMAC(sync.recieveKey, json.toString())))
					{
				    	String userId=json.get("user_id").toString();
						user.setUserId(userId.toString());
						JSONObject obj=userOp.addUser(user);
						
						if(obj!=null) 
						{			
							
							log.severe("User Registration succesful");
							resp.put("message", "User registered successfully");
							response.setStatus(200);
							resp.put("success", true);
							resp.put("code",200);
							
							}
						else
						{	
								log.severe("User already present");
								resp.put("message", "User already present");
								response.setStatus(400);
								resp.put("success", false);
								resp.put("code",400);
						}
					}
					else
					{
						response.sendError(401);
					}
			
				}
				else if(Origin!=null && ( Origin.equals("http://localhost:8080") || Origin.equals("https://georgefulltraining12.uc.r.appspot.com")))
				{
					user.setUserId(id.toString());
					JSONObject obj=userOp.addUser(user);
					if(obj!=null)
					{
							
						if(inboundAppId==null || !(inboundAppId.equals("malkarajtraining12") ))
						{
				             //Creating Request and adding necessery headers
							  final String uri="https://malkarajtraining12.uc.r.appspot.com/register";
				              URL url=new URL(uri);
				              FetchOptions options = FetchOptions.Builder.withDefaults();
				              options.setDeadline(10d);
				              options.doNotFollowRedirects();
				   			  HTTPRequest req = new HTTPRequest(url, HTTPMethod.POST,options);
	                          JSONObject reqObj=new JSONObject();
							  reqObj.put("email", email);
							  reqObj.put("password", pass);
							  reqObj.put("user_id", id);
							  req.setPayload(reqObj.toString().getBytes());
							  req.addHeader(new HTTPHeader("Authorization", hash.calculateHMAC(sync.sentKey, reqObj.toString())));
							  //
							  
							  resp=sync.sentRequest(req);
							  if(resp.get("success").toString().equals("true"))
								{
									log.info("User succesfully registered in cross domain");
									resp.put("detail", obj);
									response.setStatus(200);
								}
							  else
								{
									log.severe("User registration failed due to exceeding retry limit");
									response.setStatus(Integer.parseInt(resp.get("code").toString()));
								}						
						}							
						
					}
					else
					{	
							log.severe("User already present");
							resp.put("message", "User already present");
							response.setStatus(400);
							resp.put("success", false);
							resp.put("code",400);
					}
				}
				else
				{
					resp.put("success", false);
					resp.put("code", 401);
					resp.put("detail", "You are not authorized to use this API");
				}
				out.println(resp);
        
		} 
       catch(SocketTimeoutException s)
       {
           JSONObject obj=new JSONObject();
           response.setStatus(500);
           obj.put("success", false);
           obj.put("code", 500);
           obj.put("message", "Socket Timeout");
           out.println(obj);   	
       }
       
       
       catch (Exception q) {
          JSONObject obj=new JSONObject();
          response.setStatus(400);
          obj.put("success", false);
          obj.put("code", 400);
          obj.put("message", "Invalid user");
          out.println(obj);
          q.printStackTrace();
	}
             
   }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException 
    { 
        // pre-flight request processing
        resp.setHeader("Access-Control-Allow-Origin", "https://malkarajtraining12.uc.r.appspot.com/");
        resp.setHeader("Access-Control-Allow-Methods", "POST");
        resp.setHeader("Access-Control-Allow-Headers", "*");
        System.out.println("in preflight");
    }


}
