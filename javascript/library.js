/**
 * Copyright Adrian Hayes 2012
 * 
 * This file is part of BurpJS.
 * BurpJS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BurpJS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with BurpJS.  If not, see <http://www.gnu.org/licenses/>.
 */


var burpInterface

var getTemplate =
"GET <%%relative_url%%> HTTP/1.1\r\n\
Host: <%%host%%>\r\n\
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.19) Gecko/20110420 Firefox/3.5.19)\r\n\
<%%cookie%%>\r\n\r\n"

var postTemplate = 
"POST <%%relative_url%%> HTTP/1.1\r\n\
Host: <%%host%%>\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.19) Gecko/20110420 Firefox/3.5.19\r\n\
<%%cookie%%>\r\n\
Content-Type: application/x-www-form-urlencoded\r\n\
Content-Length: <%%content_length%%>\r\n\
\r\n\
<%%data%%>"


function setBurpInterface(bInt) {
	burpInterface = bInt
}


function print(str) {

	if (typeof str == 'undefined')
		str = '<cannot print undefined>'

	if (typeof str.toString != 'function') {
		throw new org.mozilla.javascript.JavaScriptException("Error: can't convert to string so can't print.")
		return;	
	}

	java.lang.System.out.print(str.toString())

}

function println(str) {
	if (str)
		print(str)
	print('\n')
}



function alert(message) {
	burpInterface.issueAlert(message)
}


function makeHttpRequest(url, postData, cookie) {
	
	var parts = parseUri(url)
	var useHttps = parts['protocol'].toLowerCase() == 'https://'
	var host = parts['host']
	var port = parts['port']
	var path = parts['path']
	var getParams = parts['query'] ? '?' + parts['query'] : ''
	
	if (!port)
		port = useHttps ? 443 : 80
	
	var template = postData ? postTemplate : getTemplate
	var request = ''

	request = template.replace('<%%relative_url%%>', path + getParams)
	request = request.replace('<%%host%%>', host)

	if (postData) {
		request = request.replace('<%%content_length%%>', postData.length)
		request = request.replace('<%%data%%>', postData)	
	}		

	if (cookie)
		request = request.replace('<%%cookie%%>', 'Cookie: ' + cookie)
	else
		request = request.replace('\r\n<%%cookie%%>', '')
	
	burpInterface.makeHttpRequest(host, port, useHttps, request.getBytes('UTF-8'));
	
}

//Gets cookie values from http request (using Cookie
//header) or response (using Set-Cookie header)
function getCookies(httpMessage) {

	var cookies = {}
	
	var headers = httpMessage.getHeaders()
	for (header in headers) {
		var header = headers[header]
		
		//for http requests
		if (header.startsWith('Cookie:')) {
			var tokens = header.split(' ')
			for (var i = 1; i < tokens.length; i++) { //i = 1 because first token is 'Cookie:' which we don't want
				var token = tokens[i]
				if (token.endsWith(';')) 
					token = token.slice(0,-1)
				var [key, value] = token.split('=')
				cookies[key] = value
			}
		}

		//for http responses
		if (header.startsWith('Set-Cookie:')) {

			var [key, value] = header.split(' ')[1].split('=')
			if (value.endsWith(';')) 
				value = value.slice(0,-1)
				
			cookies[key] = value
		}
	}
	
	return cookies
}


//takes output from 'getCookies' (or an associative array) and creates a string that can be used in a cookie http header
function buildCookieString(cookies) {

	if (!cookies)
		return

	var str = ''
	for (name in cookies)
		str += name + '=' + cookies[name] + '; ' 
	
	
	return str
}


//Base64 encode a byte array (this is an array of numbers from -127 to 127 representing a byte).
function base64ArrayEncode(byteArray) {
	if (!byteArray instanceof Array)
		throw new org.mozilla.javascript.JavaScriptException("Error: Cannot Base64 encode an object that is not a java-ish byte array.")
		
	return Packages.burp.Base64.encodeBytes(byteArray)
}

//Decode a Base64 string into a Java byte array.
function base64ArrayDecode(str) {
	return Packages.burp.Base64.decode(str)
}


//----------------------------------------------
//patch in some methods
//----------------------------------------------
String.prototype.getBytes = function(encoding) {
	return new java.lang.String(this).getBytes(encoding)
} 

String.prototype.startsWith = function(str) {
	return new java.lang.String(this).startsWith(str)
} 

String.prototype.endsWith = function(str) {
	return new java.lang.String(this).endsWith(str)
}


