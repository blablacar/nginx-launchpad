DataDome Nginx Module
==========================

v2.34 (2018-05-10)
-----------------
 - Included headers to ApiServer's call: Content-Type, From, X-Real-IP, Via and True-Client-IP
 - Changed the logic to truncate X-Forwarded-For from beginning

v2.33 (2017-08-07)
------------------
 - Introduced support 401 response code from the API Server

v2.32 (2017-04-12)
------------------
- Introduced data_dome_auth_set

v2.31 (2017-03-24)
------------------
 - Reduce traffic size between module and APIServer

v2.30 (2017-03-21)
------------------
 - Added compatibility with nginx before 1.5.8, 1.5.6 and 1.5.3
 - Removed warnings for nginx before 1.9.11

v2.29 (2017-03-16)
------------------
 - Implemented support X-DataDome-request-Headers

v2.28 (2017-02-08)
------------------
 - Don't mark as inactive API server's backend for 10 second in case of any error

v2.27 (2016-12-09)
------------------
 - Added verification by X-DatadomeResponse header
 - Sent request's headers name to the API server
 - Sent request's Connection, Pragma and Cache-Control header's value

v2.26 (2016-11-30)
------------------
 -  `data_dome_auth` supports disable processing request by setting 'off' up over variable

v2.25 (2016-11-25)
------------------
 - Fixed possible segfault on large API server response
 - data_dome_auth directive accepts variables

v2.24 (2016-11-04)
------------------
 - Sync version

v2.23 (2016-10-18)
------------------
 - Fixed default exclusion regex for match file likes some.min.css

v2.22 (2016-09-26)
------------------
 - correct truncate url encoded value

v2.21 (2016-09-21)
------------------
 - Decreased the maximum API call to 10kb

v2.20 (2016-09-13)
------------------
 - Add .mp4 and .otf to default exclusion regex

v2.19 (2016-08-08)
------------------
 - Remove all code that can read request body
 - Add regex exclusion

v2.18 (2016-07-27)
------------------
 - Send Content-Length header as PostParamLen

v2.17 (2016-06-29)
-------------------
 - Disable send Cookies and Body to API server by default
 - Add debug_params option
 - Send Cookies length and Body length to API server
 - Send Authorization length
 - Send Method
 - Send X-Requested-With
 - Send Origin

v2.16 (2016-06-28)
-------------------
 - Added debug mode

v2.15 (2016-06-23)
-------------------
 - Add url encoding to API call parametrs
 
v2.14 (2016-06-03)
-------------------
 - Fix param truncate logic

v2.13 (2016-04-25)
-------------------
 - Don't overwrite Set-Cookie header.

v2.12 (2016-04-15)
-------------------
 - Module don't generate ClientID
 - Remove X-DataDome header with module version
 - Support X-DataDome-headers from API response

v2.11 (2016-04-09)
-------------------
 - Implemented dynamic server based on https://github.com/GUI/nginx-upstream-dynamic-servers
 - Implemented $data_dome_auth_is_uri_regex_matched variable
 - Add X-DataDome header with module version

v2.10 (2016-04-07)
-------------------
 - Add support dynamic module

v2.9 (2016-03-31)
-------------------
 - Don't call the API server several times

v2.8 (2016-03-30)
-------------------
 - Finalize request after send API server response

v2.7 (2016-03-29)
-------------------
 - don't finalize HTTP request two time with different status

v2.6 (2016-01-28)
-------------------
 - re-generate client ID if it shortest or longest what expected

v2.5 (2016-01-08)
-------------------
 - fixed bug when nginx doesn't sent response to client when API server responsed not 200 without a body

v2.4 (2016-01-08)
-------------------
 - synchronize version with apache and varnish module

v2.3 (2016-01-06)
-------------------
 - fixed build with IPv6
 - fixed build on GCC-4.8
 - fixed post_param_limit
 - don't send '\0' as end of one of parametrs to API Server call
 - uses ip address for client id generation if can't parse X-Forwarder-For
 - memzero new headers and potentian crash
 - fixed potential connection leaks
 - sent to client API response for 301, 302 and 403 response
 - sent to client location from API response for 301 and 302 response
 
v2.2 (2015-12-10)
-----------------
 - fixed crash X-Forwarder-For without port
 - don't send empty parameter anymore

v2.1 (2015-12-02)
-----------------
 - Regex only apply to URL, not to MIME anymore

V2.0 (2015-11-30)
-----------------
 - Cookie and session ID implementation
 - Extract more from Header : Accept, AcceptCharset, AcceptEncoding and AcceptLanguage
