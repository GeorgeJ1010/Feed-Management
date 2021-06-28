package com.feed;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;



@WebFilter("/RegisterFilter")
public class RegisterFilter implements Filter {

	static Logger logger = Logger.getLogger("logger");
    public RegisterFilter() {
    }


	public void destroy() {
	}


	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String appId=req.getHeader("X-Appengine-Inbound-Appid");
        
        if(req.getMethod().equalsIgnoreCase("POST"))
        {
	            
	        if(appId!=null && appId.equals("malkarajtraining12"))
	        {
	        	chain.doFilter(request, response);
	        	logger.info("appdId:"+appId);
	        }
	        else
	        {
	        	logger.info("else part");
	        	chain.doFilter(request, response);
	
	        }
        }
        else
        {
        	chain.doFilter(request, response);

        }

        /* 
	    StringBuffer jb = new StringBuffer();
	    PrintWriter out=response.getWriter();
	    String line = null;
	    BufferedReader reader = req.getReader();
	    while ((line = reader.readLine()) != null)
	        jb.append(line);
	    String message=jb.toString();
        
        
        if(req.getMethod().equalsIgnoreCase("POST"))
        {
            
	
	        SyncApp sync= new SyncApp();
            String Origin=req.getHeader("Origin");
            String appId=req.getHeader("X-Appengine-Inbound-Appid");
            if(appId!=null)
            {
            	logger.info("appdId:"+appId);
            }
            else
            {
            	logger.info("no app id present");
            }
            
	        if(Origin!=null && (Origin.equals("http://localhost:8080") || Origin.equals("https://georgefulltraining12.uc.r.appspot.com")))
	        {
	            logger.info("register API request from same-origin");
	    		chain.doFilter(request, response);
	
	        }
	        else
	        {
	        	HMACAlgorithm hash=new HMACAlgorithm();
                String token=req.getHeader("Authorization");            
	        	if(token!=null && token==hash.calculateHMAC(sync.recieveKey,message))
	        	{
	                logger.info("Authorization succesfull");
	        		chain.doFilter(request, response);
	        	}
	        	else
	        	{
	                logger.severe("register API request from unknown Origin");
	        		res.sendError(HttpServletResponse.SC_FORBIDDEN);
	        	}
	        	
            }


        }
        else
        {
        	chain.doFilter(request, response);

        }
*/

	}


	public void init(FilterConfig fConfig) throws ServletException {
	}


}
