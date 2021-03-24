# About Libesphttpd

Libesphttpd is a HTTP server library for the ESP8266/ESP32. It supports
integration in projects running under the FreeRTOS-based SDKs. Its core is
clean and small, but it provides an extensible architecture with plugins like
a tiny template engine, websockets, a captive portal, and more.

# Examples

There is a [FreeRTOS-based](https://github.com/chmorgan/esphttpd-freertos)
example. It shows how to use libesphttpd to serve files from ESP8266/ESP32 and
illustrate a way to allow a user to associate the ESP8266/ESP32 with an access
point from a standard webbrowser on a PC or mobile phone.

There is also a [Linux](https://github.com/chmorgan/libesphttpd_linux_example)
example.

# Using with ESP-IDF

Check out the libesphttpd repository in the components directory of your
project. This should put it at my_project/components/libesphttpd. If it is in
the correct location you should see a 'ESP-HTTPD Config' entry under
'Component config' when you run 'idf.py menuconfig' in ESP-IDF project.

# SSL Support

libesphttpd supports https under FreeRTOS via OpenSSL and MbedTLS. Server and
client certificates are supported.

Enable 'EHTTPD_SSL_OPENSSL' or 'EHTTPD_SSL_MBEDTLS' during project
configuration.

See the [How to configure and use SSL](#how-to-configure-and-use-ssl) section
below.

# Programming Guide

Programming libesphttpd will require some knowledge of HTTP. Knowledge of the
exact RFCs isn't needed, but it helps if you know the difference between a GET
and a POST request, how HTTP headers work, what a mime-type is and so on.
Furthermore, libesphttpd is written in the C language and uses the libraries
available on the ESP8266/ESP32 SDKs. It is assumed the developer knows C and
has some experience with the SDK.

## Initializing libesphttpd

Initialization is done by the
`ehttpd_init(routes, addr, conn_buf, conn_max, flags)` call, which returns an
instance pointer. The routes is a list of url handlers. addr is the address to
listen on, which can be NULL to listen on 0.0.0.0:80 or 0.0.0.0:443 depending
if TLS is enabled or not. conn_buf is pointer to memory to use for connection
data. It can be statically allocated, dynamically allocated, or NULL if you
wish to have the pool managed automatically. conn_max is the maximum number of
concurrent connections allowed. flags can be set to EHTTPD_FLAG_TLS to enable
TLS.

```c
const ehttpd_route_t routes[] = {
    {"/",          ehttpd_route_redirect, "/index.cgi", NULL},
    {"/index.cgi", my_route_function,     NULL,         NULL},
    {"*",          ehttpd_route_fs_get,   "/spiffs",    NULL},
    {NULL,         NULL,                  NULL,         NULL}
};
```

As you can see, the array consists of a number of entries, with the last entry
filled with NULLs. When the webserver gets a request, it will run down the
list and try to match the URL the browser sent to the pattern specified in the
first argument in the list. If a match is detected, the corresponding route is
called. This function gets the opportunity to handle the request, but it also
can pass on handling it; if this happens, the webserver will keep going down
the list to look for a route with a matching pattern willing to handle the
request; if there is none on the list, it will generate a 404 page itself.

The patterns can also have wildcards: a * at the end of the pattern matches
any text. For instance, the pattern `/wifi/*` will match requests for
`/wifi/index.cgi` and `/wifi/picture.jpg`, but not for example
`/settings/wifi/`. The ehttpd_route_fs_get is used like that in the
example: it will be called on any request that is not handled by the route
earlier in the list.

There is also two additional entries in a route. These are optional arguments
for the route; its purpose differs per specific function. If this is not
needed, it's okay to put NULL there instead.

## How to configure and use SSL

### How to create certificates
SSL servers require certificates. Steps to use:

  * Place a 'cacert.der' and 'prvtkey.der' files in your app directory.

  * To create self certified certificates:

        openssl req -sha256 -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

  * To generate .der certificates/keys from .pem certificates/keys:

        openssl x509 -outform der -in certificate.pem -out certificate.der
        openssl rsa -outform der -in key.pem -out key.der

### Compile certificates into your binary image (option 1)

  * Create a 'component.mk' file in your app directory and add these lines to
    it:

        COMPONENT_EMBED_TXTFILES := cacert.der
        COMPONENT_EMBED_TXTFILES += prvtkey.der

And use the below code to gain access to these embedded files. Note the
filename with extension is used to generate the binary variables, you can
modify the embedded filenames but make sure to update the
_binary_xxxx_yyy_start and end entries:

```c
extern const unsigned char cacert_der_start[] asm("_binary_cacert_der_start");
extern const unsigned char cacert_der_end[]   asm("_binary_cacert_der_end");
const size_t cacert_der_bytes = cacert_der_end - cacert_der_start;

extern const unsigned char prvtkey_der_start[] asm("_binary_prvtkey_der_start");
extern const unsigned char prvtkey_der_end[]   asm("_binary_prvtkey_der_end");
const size_t prvtkey_der_bytes = prvtkey_der_end - prvtkey_der_start;
```

### Store / load certificates to a filesystem (option 2)
See the mkspiffs documentation for more information on creating a spiffs
filesystem and loading it at runtime.

Otherwise use standard file functions, fopen/fread/fclose to read the
certiricates into memory so they can be passed into libesphttpd.

### Load the server certificate and private key
```c
    // load the server certificate and private key
    ehttpd_set_cert_and_key(inst, cacert_der_ptr, cacert_der_size,
            prvtkey_der_ptr, prvtkey_der_size);
```

### Optionally enable client certificate validation

You can embed client certificates into the flash image or store them in a
filesystem depending on your need.

```c
    ehttpd_set_client_validation(inst, true);
    ehttpd_add_client_cert(inst, client_certificate_ptr, client_cert_len);
```

## Writing a route handler

A route handler, in principle, is called when the HTTP headers have come in
and the client is waiting for the response of the webserver. The route handler
is responsible for generating this response, including the correct headers and
an appropriate body. To decide what response to generate and what other
actions to take, the route handler can inspect various information sources,
like data passed as GET- or POST-arguments.

A simple route handler may, for example, greet the user with a name given as
a GET argument:

```c
ehttpd_status_t my_route_greet_user(ehttpd_conn_t *conn) {
    ssize_t len;        // length of user name
    char name[128];     // Temporary buffer for name
    char output[256];   // Temporary buffer for HTML output

    // If the browser unexpectedly closes the connection, the route handler
    // will be called after the isConnectionClosed flag is set. We can use
    // this to clean up any data. It's not used in this simple route handler.
    if (conn->closed) {
        //Connection aborted. Clean up.
        return EHTTPD_STATUS_DONE;
    }

    if (conn->method!=EHTTPD_METHOD_GET) {
        //Sorry, we only accept GET requests.
        ehttpd_start_response(conn, 406);  //http error code 'unacceptable'
        ehttpd_end_headers(conn);
        return EHTTPD_STATUS_DONE;
    }

    // Look for the 'name' GET value. If found, urldecode it and return it
    // into the 'name' var.
    len = sizeof(name);
    len = ehttpd_find_param("name", conn->args, name, &len);
    if (len == -1) {
        // If the result of ehttpd_find_arg is -1, the variable isn't found
        // in the data.
        strcpy(name, "unknown person");
    }

    // Generate the header
    // We want the header to start with HTTP code 200, which means the
    // document is found.
    ehttpd_start_response(conn, 200);

    // We are going to send some HTML.
    ehttpd_header(conn, "Content-Type", "text/html");

    // No more headers.
    ehttpd_end_headers(conn);

    // We're going to send the HTML as two pieces: a head and a body. We
    // could've also done it in one go, but this demonstrates multiple ways of
    // calling ehttpd_enqueue_text. Send the HTML head. Using -1 as the length
    // will make ehttpd_enqueue_text take the length of the zero-terminated
    // string it's passed as the amount of data to send.
    ehttpd_enqueue(conn, "<html><head><title>Page</title></head>", -1)

    // Generate the HTML body.
    len = sprintf(output, "<body><p>Hello, %s!</p></body></html>", name);

    // Send HTML body to webbrowser. We use the length as calculated by
    // sprintf here. Using -1 again would also have worked, but this is more
    // efficient.
    ehttpd_enqueue(conn, output, len);

    // All done.
    return EHTTPD_STATUS_DONE;
}
```

Putting this route handler into the ehttpd_route_t array, for example with
pattern `"/hello.cgi"`, would allow an user to request the page
`"http://192.168.4.1/hello.cgi?name=John+Doe"` and get a document saying
*"Hello, John Doe!"*.

A word of warning: while it may look like you could forego the entire
ehttpd_start_response/ehttpd_header/ehttpd_end_header structure and send
all the HTTP headers using ehttpd_enqueue_text, this will break a few things
that need to know when the headers are finished, for example the HTTP 1.1
chunked transfer mode.

The approach of parsing the arguments, building up a response and then sending
it in one go is pretty simple and works just fine for small bits of data.
The gotcha here is that all http data sent during the route handler (headers
and data) are temporarily stored in a buffer, which is sent to the client when
the function returns. The size of this buffer is typically about 2K; if the
handler tries to send more than this, data will be lost.

The way to get around this is to send part of the data using
`ehttpd_enqueue_text` and then return with `EHTTPD_STATUS_MORE` instead of `EHTTPD_STATUS_DONE`. The webserver will send the partial data and will call
the route handler again so it can send another part of the data, until the
route handler finally returns with `EHTTPD_STATUS_DONE`. The route can store
it's state in conn->user, which is a freely usable pointer that will persist
across all calls in the request. It is NULL on the first call, and the
standard way of doing things is to allocate a pointer to a struct that stores
state here. Here's an example:

```c
typedef struct {
    char *string_pos;
} my_state_t;

static char *long_string = "Please assume this is a very long string, way " \
        "too long to be sent in one time because it won't fit in the send " \
        "buffer in it's entirety; we have to break up sending it in " \
        "multiple parts.";

ehttpd_status_t route_send_long_string(ehttpd_conn_t *conn) {
    my_state_t *state = conn->user;
    size_t len;

    // If the browser unexpectedly closes the connection, the route handler
    // will be called after isConnectionClosed is set to true. We can use this
    // to clean up any data. It's pretty relevant here because otherwise we
    // may leak memory when the browser aborts the connection.
    if (conn->closed) {
        //Connection aborted. Clean up.
        if (state != NULL) {
            free(state);
        }
        return EHTTPD_STATUS_DONE;
    }

    if (state == NULL) {
        // This is the first call to the route handler for this webbrowser
        // request. Allocate a state structure.
        state = malloc(sizeof(mu_state_t);

        // Save the ptr in conn so we get it passed the next time as well.
        conn->user = state;

        // Set initial pointer to start of string
        state->string_pos = long_string;

        // We need to send the headers before sending any data. Do that now.
        ehttpd_start_response(conn, 200);
        ehttpd_header(conn, "Content-Type", "text/plain");
        ehttpd_end_headers(conn);
    }

    // Figure out length of string to send. We will never send more than 128
    // bytes in this example.
    len = strlen(state->stringPos); // Get remaining length
    if (len > 128) {
        len = 128; // Never send more than 128 bytes
    }

    // Send that amount of data
    ehttpd_enqueue(conn, state->string_pos, len);

    // Adjust stringPos to first byte we haven't sent yet
    state->string_pos += len;

    // See if we need to send more
    if (strlen(state->string_pos) != 0) {
        // we have more to send; let the webserver call this function again.
        return EHTTPD_STATUS_MORE;
    } else {
        // We're done. Clean up here as well: if the route handler returns
        // EHTTPD_STATUS_DONE, it will not be called again.
        free(state);
        return EHTTPD_STATUS_DONE;
    }
}

```

TODO: non-os stuff follows

In this case, the route is called again after each chunk of data has been sent
over the socket. If you need to suspend the HTTP response and resume it
asynchronously for some other reason, you may save the `ehttpd_conn_t`
pointer, return `EHTTPD_STATUS_MORE`, then later call `ehttpd_continue` with
the saved connection pointer. For example, if you need to communicate with
another device over a different connection, you could send data to that device
in the initial route call, then return `EHTTPD_STATUS_MORE`, then, in the
`espconn_recv_callback` for the response, you can call `ehttpd_continue` to
resume the HTTP response with data retrieved from the other device.

For POST data, a similar technique is used. For small amounts of POST data
(smaller than MAX_POST, typically 1024 bytes) the entire thing will be
stored in `conn->post->buf` and is accessible in its entirely on the first
call to the route handler. For example, when using POST to send form data, if
the amount of expected data is low, it is acceptable to do a call like the
following to get the data for the individual form elements:

```c
ssize_t len = sizeof(buf)
len = ehttpd_find_param("varname", conn->post->buf, buf, &len);
```

In all cases, `conn->post->len` will contain the length of the entirety of the
POST data, while `conn->post->buf_len` contains the length of the data in
`conn->post->buf`. In the case where the total POST data is larger than the
POST buffer, the latter will be less than the former. In this case, the route
handler is expected to not send any headers or data out yet, but to process
the incoming bit of POST data and return with `EHTTPD_STATUS_MORE`. The next
call will contain the next chunk of POST data. `conn->post->received` will
always contain the total amount of POST data received for the request,
including the data passed to the route handler. When that number equals
`conn->post->len`, it means no more POST data is expected and the route
handler function is free to send out the reply headers and data for the
request.

## The template engine

The espfs driver comes with a tiny template engine, which allows for
runtime-calculated value changes in a static html page. It can be included in
the builtInUrls variable like this:

```c
    {"/showname.tpl", ehttpd_route_fs_template, tpl_show_name, NULL},
```

It requires two things. First of all, the template is needed, which
specifically is a file on the espfs with the same name as the first argument
of the route value, in this case `showname.tpl`. It is a standard HTML file
containing a number of %name% entries. For example:

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
ehttpd_status_t tpl_show_name(ehttpd_conn_t *conn, char *token, void **arg) {
    if (token == NULL) {
        return EHTTPD_STATUS_DONE;
    }

    if (os_strcmp(token, "username") == 0) {
        ehttpd_enqueue(conn, "John Doe", -1);
    } else if (os_strcmp(token, "thing") == 0) {
         ehttpd_enqueue(conn, "ESP8266/ESP32 webserver", -1);
    }

    return EHTTPD_STATUS_DONE;
}
```

This will result in a page stating *Welcome, John Doe, to the ESP8266/ESP32
webserver!*

## Websocket functionality

ToDo: document this

# Linux Support

Lwip provides a POSIX interface that matches that of a Linux system. FreeRTOS
primitives are also similiar to those provided under POSIX. But also FreeRTOS
can run on Linux.

Running on a Linux system enables testing under a range of different
conditions including different native pointer sizes (64bit vs. 32bit), as
well as with different compilers. These differences can help reveal
portability issues.

Linux tools such as valgrind can be used to check for memory leaks that would
be much more difficult to detect on an embedded platform. Valgrind and other
tools also provide ways of looking at application performance that go beyond
what is typically available in an embedded environment.

See https://github.com/chmorgan/libesphttpd_linux_example for an example of
how to use libesphttpd under Linux.

# Licensing

libesphttpd is licensed under the MPLv2. It was originally licensed under a
'Beer-ware' license by Jeroen Domburg that was equivalent to a public domain
license. Chris Morgan <chmorgan@gmail.com> initiated relicensing to MPLv2
prior to investing a number of hours into improving the library for its use in
a potential commercial project. The relicensing was done after asking for and
receiving the blessing from most of the projects contributors although it
should be noted that the original license didn't require permission to
relicense or use in any way.

The topic of licenses can be controversial. The original license was more
free in that it allowed users to use the code in any way, including
relicensing it to any license they chose. The MPLv2 restricts freedom in that
it requires modifications to be given back to the community. This license
establishes the agreement that in exchange for using this great library that
users are required to give back their changes to let others benefit. This was
the spirit and intention of the relicencing to the MPLv2.

While the 'Beer-ware' license text was removed to avoid license confusion the
authors of this great library, especially Jeroen, deserve a beer. If you
appreciate the library and you meet them in person some day please consider
buying them a beer to say thanks!
