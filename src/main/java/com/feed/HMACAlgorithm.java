package com.feed;


import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.appengine.repackaged.com.google.api.client.util.Base64;

public class HMACAlgorithm {
	
	private final static String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final Logger log = Logger.getLogger("logger");	

	public String calculateHMAC(String secret, String data) {
		try {
			SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(),	HMAC_SHA1_ALGORITHM);
			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			mac.init(signingKey);
			byte[] rawHmac = mac.doFinal(data.getBytes());
			String result = new String(Base64.encodeBase64(rawHmac));
			return result;
		} catch (GeneralSecurityException e) {
			log.warning("Unexpected error while creating hash: " + e.getMessage());
			throw new IllegalArgumentException();
		}
	}

}
