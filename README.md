 1 Why mod_auth_ofba
 ===================

When using Microsoft Office with a WebDAV share, Office programs
will prompt for authentication each time they are started, even if
the share is already mounted.

The only way to prevent all behavior implement Microsoft Office
Forms Based Authentication (OFBA) protocol.  This is what this
modules implements.

MS-OFBA is documented here
https://msdn.microsoft.com/en-us/library/office/cc313069%28v=office.12%29.aspx


 2 Building and installing mod_auth_ofba
 =======================================
## Option 1: Use attached Dockerfile
Use the provided Dockerfile to build and install mod_auth_ofba module based on httpd Alpine image.

**Hint: Neither basic auth credentials, nor login or success HTMLs are included, please change config according to your needs.**

### Run configuration
#### Alpine
```bash
docker build -t mod_auth_ofba -f alpine.Dockerfile .
```
#### Debian
```bash
docker build -t mod_auth_ofba -f debian.Dockerfile .
```

## Option 2: Use plain make install
Just run usual configure && make && make install

You may need to provide apxs path using --with-apxs
and APR compilation options using APR_CFLAGS and APR_LIBS

For instance:
./configure --with-apxs=/weird/bin/apxs APR_CFLAGS=-I/weird/bin/include/apr-1 \
            APR_LIBS="-L/weird/lib -lapr-1"


 3 Apache configuration
 ======================

## Required configuration

You must at least set the AuthOFBAenable, AuthOFBAauthRequestURL and
AuthOFBAauthSuccessURL options.

| Option | Description | Example |
| ------ | ----------- | ------- |
| AuthOFBAenable | Enable mod_auth_ofba (on, off) | On |
| AuthOFBAauthRequestURL | URL or location path for authentication of OFBA-capable clients. It must be protected by authentication such as Form or Basic. | https://www.my-server.com/login.aspx?wreply=https://www.my-server.com/OnSuccess.aspx |
| AuthOFBAauthSuccessURL | URL or location path reached on authentication success. | https://www.my-server.com/OnSuccess.aspx |

If the client reaches AuthOFBAauthSuccessURL and is authenticated,
mod_auth_ofba will send an OFBA session cookie. All OFBA-capable
applications (Word, Excel, PowerPoint...) have shared access to
this cookie and get authenticated without prompts while the session
is valid.

NB: During actual OFBA authentication, AuthOFBAauthRequestURL is 
    appended with parameters that include AuthName. Authentication
    will break if AuthName is not the same for the requested 
    directory and for the server root.

## Forward path parameters to request URL

You can add additional path parameters to any file request which will be forwarded as query parameters to request URL. They are separated with a semicolon and have to be placed in file path following this regex pattern:
```
(.*)/==(.+)==/(.*)
```

You will need an AliasMatch to map to the correct file path in WebDav without path parameters (see sample httpd.conf section and example.conf).

### Example
Assuming AuthOFBAauthRequestURL is set to the example above (https://www.my-server.com/login.aspx?wreply=https://www.my-server.com/OnSuccess.aspx).

A file request with the path params "param1=foo" and "param2=bar" will we done as follows:
```
https://www.my-server.com/somepath/==param1=foo;param2=bar==/file.docx
```
And will result in the following request URL:
```
https://www.my-server.com/login.aspx?wreply=https://www.my-server.com/OnSuccess.aspx&param1=foo&param2=bar
```

## Other options

| Option | Description | Default |
| ------ | ----------- | ------- |
| AuthOFBAdialogSize | Authentication dialog size, if using Form authentication | 320x130 |
| AuthOFBAcookieName | OFBA session cookie name | OFBAsession |
| AuthOFBAcookiePath | OFBA session cookie path | / |
| AuthOFBAusePersistentCookies | Use persistent cookies instead of session cookies | On |
| AuthOFBAsessionDuration | OFBA session lifetime in seconds | 86400 |
| AuthOFBAsessionAutoRenew | Automatically refresh session lifetime on each request | Off |
| AuthOFBAsessionFile | Session file path | /var/run/mod_auth_ofba.db |
| AuthOFBAlockFile | Lock file path | /var/run/mod_auth_ofba.lock |
| AuthOFBAenforceHTTPS | Enforce HTTPS connections | Off |
| AuthOFBAhttpsPort | HTTPS port of enforced connections (only needed when different from standard port) | 443 |

Additionally, the no-ofba environment variable can be set (e.g.: with SetEnvIf) to disable OFBA in some situations.

## Sample httpd.conf section

```
AliasMatch "^/(.+)/==(.+)==$" "/var/protected/$1/"
AliasMatch "^/(.+)/==(.+)==/(.*)$" "/var/protected/$1/$3"
Alias / "/var/protected/"
<Directory "/var/protected/">
  Dav filesystem
  Header add MS-Author-Via "DAV"
  Setenv "redirect-carefully"

  AuthType Basic
  AuthName "WebDAV share"
  AuthBasicProvider ldap

  AuthLDAPURL
    "ldaps://ldap.example.net/o=example?uid?sub?objectClass=inetOrgPerson"
  AuthLDAPRemoteUserAttribute uid

  Require valid-user

  AuthOFBAenable On
  AuthOFBAauthRequestURL /auth/index.html
  AuthOFBAauthSuccessURL /auth/success.html
</Directory>
```

NB: Using HTTP Basic authentication, mod_auth_ofba will redirect
    authenticated requests to AuthOFBAauthRequestURL, hence there it
    nothing to implement here. If using Form authentication, then
    AuthFormLoginRequiredLocation and AuthFormLoginSuccessLocation
    must be properly setup. See mod_auth_form documentation.


 4 ofba_session command line tool
 ================================

The ofba_session lets the administrator examine and modify session data

Usage: ofba_session [-|] [-u user] [-c cookie]
  -l        list sessions
  -u user   kill sessions by user
  -c cookie kill session by cookie

NB: Concurrent access to the session file by Apache and ofba_session is
    not protected by a mutex. Modifying sessions (-u and -c flags) while
    Apache is running may cause buggy behavior.


 5 Windows configuration
 =======================

In order to get automatic Windows login credentials sent to the WebDAV
server, two registry keys must be edited:

- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters
  Here set AuthForwardServerList to the list of trusted WebDAV server.
  Wild cards are accepted, for instance: https://*.example.net 

- HKEY_CURRENT_USER\Software\Microsoft\Office\{OFFICE_VERSION}\
      Common\Internet\WebServiceCache\FileUrl
  Here set keys with the names of your choixe, each containing a
  trusted WebDAV share, such as https://webdav.example.net/share