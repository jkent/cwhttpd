Connection
==========

`cwhttpd/httpd.h`

Functions
^^^^^^^^^

.. doxygenfunction:: cwhttpd_plat_is_ssl
.. doxygenfunction:: cwhttpd_plat_recv
.. doxygenfunction:: cwhttpd_plat_send
.. doxygenfunction:: cwhttpd_recv
.. doxygenfunction:: cwhttpd_send
.. doxygenfunction:: cwhttpd_sendf
.. doxygenfunction:: cwhttpd_get_header
.. doxygenfunction:: cwhttpd_set_chunked
.. doxygenfunction:: cwhttpd_set_close
.. doxygenfunction:: cwhttpd_response
.. doxygenfunction:: cwhttpd_send_header
.. doxygenfunction:: cwhttpd_send_cache_header
.. doxygenfunction:: cwhttpd_chunk_start
.. doxygenfunction:: cwhttpd_chunk_end

Structures
^^^^^^^^^^

.. doxygenstruct:: cwhttpd_request_t
    :members:

.. doxygenstruct:: cwhttpd_conn_t
    :members:

.. doxygenstruct:: cwhttpd_post_t
    :members:

Enumerations
^^^^^^^^^^^^

.. doxygenenum:: cwhttpd_status_t
.. doxygenenum:: cwhttpd_method_t
