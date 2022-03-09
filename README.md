# About Clockwise HTTPd

Clockwise is a HTTP server library for the ESP8266/ESP32. It supports
integration in projects running under the FreeRTOS-based SDKs. Its core is
clean and small, but it provides an extensible architecture with plugins like
a tiny template engine, websockets, a captive portal, and more.

# Example

There is an [example](https://github.com/jkent/cwhttpd-example) that works on
ESP8266, ESP32 and Linux. It shows how to use Clockwise with FrogFS, serve
files, use websocks and in the case of the Espressif devices it also shows how
to associate WiFi and do flash updates.

# Using With ESP8266_RTOS_SDK or ESP-IDF

Check out the Clockwise repository in the components directory of your
project. This should put it at my_project/components/clockwise. If it is in
the correct location you should see a **Clockwise HTTPd** entry under
**Component config** when you run `idf.py menuconfig` in your IDF project.

# TLS Support

Clockwise supports https under FreeRTOS via MbedTLS. Both server and client
certificates are supported.

Enable **CWHTTPD_MBEDTLS** during project configuration. Note that this alone
does not enable https, you need to start a server with http support.

# Programming Guide

Programming with clockwise will require some knowledge of HTTP. Knowledge of
the exact RFCs isn't needed, but it helps if you know the difference between a
GET and a POST request, how HTTP headers work, what a mime-type is and so on.
Furthermore, Clockwise is written in the C language and uses the libraries
available on the ESP8266/ESP32 SDKs. It is assumed the developer knows C and
has some experience with the SDK.

## Initializing Clockwise

Initialization is done by the {c:func}`cwhttpd_init()` function, which returns
an httpd instance pointer. This function takes two parameters, `addr` and
`flags`. `addr` is a string of ip:port notation, or NULL if the default
address should be used, which depends on how `flags` is set. If `flags` has
`CWHTTPD_FLAG_TLS` set, the `addr` default is `0.0.0.0:443`, else it is
`0.0.0.0:80`.

### Route Handlers

Now you'll want to add some route handlers to it. This can be done with the
{c:func}`cwhttpd_route_append()` function. Route handlers can take any number
of arguments.  Some examples:

```c
    cwhttpd_route_append(inst, "/", cwhttpd_route_redirect, 1, "/index.cgi");
    cwhttpd_route_append(inst, "/index.cgi", my_route_function, 0);
    cwhttpd_route_append(inst, "*", cwhttpd_route_fs_get, 1, "/spiffs");
```

Route paths must be string literals or allocated on the heap because they are
stored as pointers. There are more route functions, such as
{c:func}`cwhttpd_route_insert()`, {c:func}`cwhttpd_route_get()` and
{c:func}`cwhttpd_route_remove()`. In most cases you probably do not need to
use these though.

Internally, routes are stored as a linked list. When the web server gets a
request, it will start with the head node and traverse the list until it
finds a path that matches. The matching route handler runs and has an
opportunity to handle the request. If it returns `CWHTTPD_STATUS_NOTFOUND`,
list traversal continues until the next path match occurs. If the end of the
list is hit, {c:func}`cwhttpd_route_404()` is called. This function is defined
with \_\_attribute\_\_((\_\_weak\_\_)) so you can re-define it within your own
code.

Paths can have simple wildcard matching. An asterik at the end of a path
matches any text. For instance, the pattern `/wifi/*` will match requests for
`/wifi/index.cgi` and `/wifi/picture.jpg`, but not, for example,
`/settings/wifi/`. The {c:func}`cwhttpd_route_fs_get()` function is used like
that in the example. It will be called on any request that is not handled by
the route earlier in the list.

### Configure TLS - Optional

Next, if you're using a TLS instance, you'll want to load a certificate and a
private key. You'll need openssl to generate and convert the certificate and
private key files.

  * To create a self signed certificate and private key:

        openssl req -sha256 -newkey rsa:4096 -nodes -keyout prvtkey.pem \
                -x509 -days 365 -out cacert.pem

  * To convert from pem format to der format:

        openssl x509 -outform der -in cacert.pem -out cacert.der
        openssl rsa -outform der -in prvtkey.pem -out prvtkey.der

The resulting certificate and private key can be stored within your
application, or they can be loaded off a filesystem. A cmake function,
`target_add_resources()`, is provided to embed files. See the
[cwhttpd-example project](https://github.com/jkent/cwhttpd-example/) which
shows how to use it.

Once you have your certificate and private key loaded or accessable, you can
call the {c:func}`cwhttpd_set_cert_and_key()` function.

```c
    cwhttpd_set_cert_and_key(inst, cacert_der, cacert_der_len, prvtkey_der,
            prvtkey_der_len);
```

### Client Certificates - Optional

You can also load client certificates and enable client validation if you
wish. Using {c:func}`cwhttpd_set_client_validation` and
{c:func}`cwhttpd_add_client_cert`.

```c
    cwhttpd_set_client_validation(inst, true);
    cwhttpd_add_client_cert(inst, client_cert_der, client_cert_der_len);
```

### Start It Up!

Finally, you'll want to start the http server. Call {c:func}`cwhttpd_start()`:

```c
    assert(cwhttpd_start(inst) == true);
```

## Writing a route handler

A route handler, in principle, is called after the HTTP headers have been
received. The route handler is responsible for receiving any POST data and
generating the response, which includes the headers and document body.

A simple route handler may, for example, greet the user with a name given as
a GET argument:

```c
cwhttpd_status_t hello_route_handler(cwhttpd_conn_t *conn) {
    ssize_t len;        // length of user name
    char name[128];     // Temporary buffer for name

    if (conn->method != CWHTTPD_METHOD_GET) {
        // Sorry, we only accept GET requests.
        cwhttpd_response(conn, 406);  // http error code 'unacceptable'
        return CWHTTPD_STATUS_DONE;
    }

    // Look for the 'name' GET value. If found, urldecode it and return it
    // into the 'name' var.
    len = sizeof(name);
    len = cwhttpd_find_param("name", conn->args, name, &len);
    if (len == -1) {
        // If the result of cwhttpd_find_arg is -1, the variable isn't found
        // in the data.
        strcpy(name, "unknown person");
    }

    // Generate the response header
    // We want the response header to start with HTTP code 200, which means
    // the document is found.
    cwhttpd_response(conn, 200);

    // We are going to send some HTML.
    cwhttpd_send_header(conn, "Content-Type", "text/html");

    // We're going to send the HTML as two pieces: a head and a body. We
    // could've also done it all in one go, but this demonstrates the two send
    // functions at our disposal. Send the HTML head using -1 as the length
    // will make cwhttpd_send use strlen() to find the length and send the
    // string without the null terminator.
    cwhttpd_send(conn, "<html><head><title>Page</title></head>", -1)

    // Send HTML body to webbrowser using the awesome cwhttpd_sendf function.
    cwhttpd_sendf(conn, "<body><p>Hello, %s!</p></body></html>", name);

    // All done.
    return CWHTTPD_STATUS_DONE;
}
```

Lets insert this as a route in our list, before the wildcard catch-all:

```c
    cwhttpd_route_insert(inst, -1, "/hello.cgi", hello_route_handler, 0);
```

This would allow allow a user to request the page
`"http://192.168.4.1/hello.cgi?name=John+Doe"` and get a document saying
*"Hello, John Doe!"*.

There are a few things that go on behind the scenes, such as automatic end of
header and chunk handling to make things a little easier.

## The Template Engine

The espfs and fs drivers come with a simple template engine that allows for
runtime-calculated values in a static html page. The route handlers are
{c:func}`cwhttpd_route_espfs_tpl` and {c:func}`cwhttpd_route_fs_tpl`. They take
two arguments, the first is the base or file path, the second is the template
replacer function.

```c
    cwhttpd_route_insert(inst, -1, "/showname.tpl", cwhttpd_route_fs_tpl, 2,
            "/", tpl_show_name);
```

First you'll need a template, which is a file located on either espfs or the
filesystem. It is a standard HTML file containing a number of %name% entries.
For example:

```html
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome, %username%, to the %thing%!</h1>
</body>
</html>
```

When this URL is requested, the words between percent characters will invoke
the `tpl_show_name` function, allowing it to output specific data. For
example:

```c
cwhttpd_status_t tpl_show_name(cwhttpd_conn_t *conn, char *token, void **user)
{
    if (strcmp(token, "username") == 0) {
        cwhttpd_send(conn, "John Doe", -1);
    } else if (strcmp(token, "thing") == 0) {
        cwhttpd_send(conn, "ESP8266/ESP32 webserver", -1);
    }

    return CWHTTPD_STATUS_DONE;
}
```

Now you'll need to install a route handler:

```c
    cwhttpd_route_insert(inst, -1, "/showname.tpl", cwhttpd_route_espfs_tpl, 2,
            "/", tpl_show_name);
    cwhttpd_route_insert(inst, -1, "/showname.tpl", cwhttpd_route_fs_tpl, 2,
            "/", tpl_show_name);
```

When browsing to `showname.tpl`, this will result in a page stating
    *Welcome, John Doe, to the ESP8266/ESP32 webserver!*

## WebSockets

WebSockets are a really nifty way to get a bi-directional persisitant
connection to a web server and they are simple to use, too. A trivial echo
server can be realized in 12 lines:

```c
void ws_echo_handler(cwhttpd_ws_t *ws)
{
    char buf[128];

    while (true) {
        ssize_t ret = cwhttpd_ws_recv(ws, buf, sizeof(buf));
        if (ret <= 0) {
            break;
        }
        cwhttpd_ws_send(ws, buf, ret, CWHTTPD_WS_FLAG_NONE);
    }
}
```

A route handler for the WebSocket could be as follows:

```c
    cwhttpd_route_insert(inst, -1, "/ws/echo.cgi", cwhttpd_route_ws, 1,
            ws_echo_handler);
```

More details in the WebSocket API documentation.

# Linux Support

Running on a Linux system enables rapid development and testing under a range
of different conditions including different native pointer sizes
(64bit vs. 32bit), as well as with different compilers. These differences can
help reveal portability issues.

Linux tools such as valgrind can be used to check for memory leaks that would
be much more difficult to detect on an embedded platform. Valgrind and other
tools also provide ways of looking at application performance that go beyond
what is typically available in an embedded environment.

See the [example project](https://github.com/jkent/cwhttpd-example) for an
example of how to use Clockwise under Linux.

# History and Licensing

Clockwise is a fork of libesphttpd by Chris Morgan, which is a fork of
esphttpd by Jeroen Domburg (also known as Sprite_tm). The former is licensed
under a 'Beer-ware' license (essentially public domain) and the later MPLv2.
Clockwise is also licensed under the MPLv2.

In the spirt of the original licensing, if you meet any of the people who have
contributed to any of these projects you should consider buying them a beer to
say thanks!
