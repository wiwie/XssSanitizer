package org.tonyzampogna.xss.sanitizer.util;

import org.owasp.esapi.ESAPI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Taken from http://ricardozuasti.com/2012/stronger-anti-cross-site-scripting-xss-filter-for-java-web-apps/
 */
public class XssSanitizerUtil {

	/**
	 * This method takes a string and strips out any potential script injections.
	 *
	 * @param value
	 * @return String - the new "sanitized" string.
	 */
	public static String stripXSS(String value) {

		try {

			if (value != null) {
				// NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
				// avoid encoded attacks.
				value = ESAPI.encoder().canonicalize(value);
				
				// Use ESAPI library to encode request parameters for use as html attributes
				value = ESAPI.encoder().encodeForHTMLAttribute(value);
//				value = ESAPI.encoder().encodeForJavaScript(value);

				// Avoid null characters
				value = value.replaceAll("\0", "");
			}

		} catch (Exception ex) {
			System.out.println("Could not strip XSS from value = " + value + " | ex = " + ex.getMessage());
		}

		return value;
	}

}
