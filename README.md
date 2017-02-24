# TLS-SIP probe

This package can be used for:

* Testing SIP server availability
* Guess username/password pair is correct 

To be honest there are several approaches to do so.

* [sipp](http://sipp.sourceforge.net/)
* [baresip](http://creytiv.com/baresip.html)
* [node_baresip](https://github.com/AlexMarlo/node_baresip)
* [sip.js](https://github.com/kirm/sip.js)

But I found them to be cumbersome for such an easy task to probe SIP server. 

SIP-TLS supports only [digest auth](https://en.wikipedia.org/wiki/Digest_access_authentication) according to RFC 2069 **without**  "quality of protection" (qop) extensions introduced in  RFC 2617.

It was tested against Asterisk, so is might be not working against other servers.

## Install

`npm i tls-sip-probe --save`

## Example
```
var sip = require("tls-sip-probe");

/**
 * sip.connect(
 *     host, 
 *     port (0 for default), 
 *     user, 
 *     password
 * );
 */

sip.connect("127.0.0.1", 0, "1000", "password", function (err, result) {
	if (!err) {
		if (result === sip.results.OK) {
   			console.log("OK");
   		}
   		if (result === sip.results.FORBIDDEN) {
   			console.log("INCORRECT USER/PASSWORD");
   		}
   }
});
```
