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

Just run usual configure && make && make install

You may need to provide apxs path using --with-apxs
and APR compilation options using APR_CFLAGS and APR_LIBS

For instance:
./configure --with-apxs=/weird/bin/apxs APR_CFLAGS=-I/weird/bin/include/apr-1 \
            APR_LIBS="-L/weird/lib -lapr-1"


 3 Apache configuration
 ======================

You must at least set the AuthOFBAenable, AuthOFBAauthRequestURL and
AuthOFBAauthSuccessURL options.

```
AuthOFBAenable           Enable mod_auth_ofba (on, off)
AuthOFBAauthRequestURL   URL or location path for authentication of 
                         OFBA-capable clients. It must be protected 
                         by authentication such as Form or Basic.
AuthOFBAauthSuccessURL   URL or location path reached on authentication
                         success.
```

If the client reaches AuthOFBAauthSuccessURL and is authenticated,
mod_auth_ofba will send an OFBA session cookie. All OFBA-capable
applications (Word, Excel, PowerPoint...) have shared access to
this cookie and get authenticated without prompts while the session
is valid.

NB: During actual OFBA authentication, AuthOFBAauthRequestURL is 
    appended with parameters that include AuthName. Authentication
    will break if AuthName is not the same for the requested 
    directory and for the server root.

Other options:

```
AuthOFBAdialogSize       Authentication dialog size, if using Form
                         authentication
AuthOFBAcookieName       OFBA session cookie name
AuthOFBAsessionDuration  OFBA session lifetime in seconds
AuthOFBAsessionAutoRenew Automatically refresh session lifetime on each request
```

Additionally, the no-ofba environment variable can be set (e.g.: with
SetEnvIf) to disable OFBA in some situations.

Sample httpd.conf section:

```
<Location>
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
  AuthOFBArealm "WebDAV share"
  AuthOFBAauthRequestURL /auth/index.html
  AuthOFBAauthSuccessURL /auth/success.html
</Location>
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