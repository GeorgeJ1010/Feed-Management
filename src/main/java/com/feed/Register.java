package com.feed;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
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
        response.setHeader("Access-Control-Expose-Headers","Origin");
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
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Allow-Headers", "*");
        response.setHeader("Access-Control-Expose-Headers","Origin");
        
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
        	String origin = request.getHeader("Origin");
	    	String email=json.get("email").toString();
			String pass=BCrypt.hashpw(json.get("password").toString(),BCrypt.gensalt(10));
	        if(v.isValidateCredentials(email))
	        {
		        DateTime now = new DateTime();
		        Date date=new Date(now.getMillis());
				user.setEmail(email);
				user.setPassword(pass);
		    	UUID id=UUID.randomUUID();

				if(origin!=null && (origin.equals("https://georgefulltraining12.uc.r.appspot.com") || origin.equals("http://localhost:8080")))
				{		
					user.setUserId(id.toString());
				}
				else
				{
			    	String userId=json.get("user_id").toString();
					user.setUserId(userId.toString());

				}
				user.setDate(date);
				user.setImage("null.png");
				user.setActive(true);
				JSONObject obj=userOp.addUser(user);
				JSONObject obj1=new JSONObject();
				
				if(obj!=null) {			
					
					log.info("User succesfully registered");
					System.out.println("Origin: "+ origin);
					
					if(origin!=null && origin.equals("https://georgefulltraining12.uc.r.appspot.com"))
					{
			              final String uri="https://malkarajtraining12.uc.r.appspot.com/register";
			              URL url=new URL(uri); 
			              
			              FetchOptions options = FetchOptions.Builder.withDefaults();
			              options.setDeadline(2d);
			              options.doNotFollowRedirects();
			   			  HTTPRequest req = new HTTPRequest(url, HTTPMethod.POST,options);
						  HMACAlgorithm hash=new HMACAlgorithm();
                          JSONObject reqObj=new JSONObject();
						  reqObj.put("email", email);
						  reqObj.put("password", pass);
						  reqObj.put("user_id", id);
						  req.setPayload(reqObj.toString().getBytes());
						  req.addHeader(new HTTPHeader("Authorization", hash.calculateHMAC(sync.sentKey, reqObj.toString())));
						  obj1=sync.sentRequest(req);
						  //obj1=sync.sentRequest(url, reqObj);
						  if(obj1.get("success").toString().equals("true"))
							{
								log.info("User succesfully registered in cross domain");
								obj1.put("detail", obj);
								response.setStatus(200);
							}
						  else
							{
								log.severe("User registration failed due to exceeding retry limit");
								response.setStatus(500);
							}						
					}
					else
					{
						obj1.put("success", true);
						obj1.put("code", 200);
						obj1.put("detail", obj);
					}


	
				}
				else
				{	
						log.severe("User already present");

						obj1.put("message", "User already present");
						response.setStatus(400);
						obj1.put("success", false);
						obj1.put("code",400);
				}
				out.println(obj1);
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
		} catch (Exception q) {
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
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Expose-Headers","Origin");
        resp.setHeader("Access-Control-Allow-Methods", "*");
        resp.setHeader("Access-Control-Allow-Headers", "*");
    }


}
