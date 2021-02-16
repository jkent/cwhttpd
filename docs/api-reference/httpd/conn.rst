Connection
==========

`libesphttpd/httpd.h`

Functions
^^^^^^^^^

.. doxygenfunction:: ehttpd_get_header
.. doxygenfunction:: ehttpd_set_chunked_encoding
.. doxygenfunction:: ehttpd_set_close
.. doxygenfunction:: ehttpd_start_response
.. doxygenfunction:: ehttpd_header
.. doxygenfunction:: ehttpd_end_headers
.. doxygenfunction:: ehttpd_add_cache_header
.. doxygenfunction:: ehttpd_prepare
.. doxygenfunction:: ehttpd_enqueue
.. doxygenfunction:: ehttpd_enqueuef
.. doxygenfunction:: ehttpd_flush
.. doxygenfunction:: ehttpd_is_ssl
.. doxygenfunction:: ehttpd_send
.. doxygenfunction:: ehttpd_disconnect

Structures
^^^^^^^^^^

.. doxygenstruct:: ehttpd_conn_t
    :members:

.. doxygenstruct:: ehttpd_post_t
    :members:

Enumerations
^^^^^^^^^^^^

.. doxygenenum:: ehttpd_status_t
.. doxygenenum:: ehttpd_method_t
