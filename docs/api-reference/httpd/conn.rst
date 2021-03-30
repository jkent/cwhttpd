Connection
==========

`libesphttpd/httpd.h`

Functions
^^^^^^^^^

.. doxygenfunction:: ehttpd_plat_is_ssl
.. doxygenfunction:: ehttpd_plat_recv
.. doxygenfunction:: ehttpd_plat_send
.. doxygenfunction:: ehttpd_recv
.. doxygenfunction:: ehttpd_send
.. doxygenfunction:: ehttpd_sendf
.. doxygenfunction:: ehttpd_get_header
.. doxygenfunction:: ehttpd_set_chunked
.. doxygenfunction:: ehttpd_set_close
.. doxygenfunction:: ehttpd_response
.. doxygenfunction:: ehttpd_send_header
.. doxygenfunction:: ehttpd_send_cache_header
.. doxygenfunction:: ehttpd_chunk_start
.. doxygenfunction:: ehttpd_chunk_end

Structures
^^^^^^^^^^

.. doxygenstruct:: ehttpd_request_t
    :members:

.. doxygenstruct:: ehttpd_conn_t
    :members:

.. doxygenstruct:: ehttpd_post_t
    :members:

Enumerations
^^^^^^^^^^^^

.. doxygenenum:: ehttpd_status_t
.. doxygenenum:: ehttpd_method_t
