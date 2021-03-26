Instance
========

`libesphttpd/httpd.h`

Functions
^^^^^^^^^

.. doxygenfunction:: ehttpd_init
.. doxygenfunction:: ehttpd_get_conn_buf_size
.. doxygenfunction:: ehttpd_start
.. doxygenfunction:: ehttpd_route_insert_head
.. doxygenfunction:: ehttpd_route_insert_tail
.. doxygenfunction:: ehttpd_route_insert_after
.. doxygenfunction:: ehttpd_route_remove
.. doxygenfunction:: ehttpd_route_remove_head
.. doxygenfunction:: ehttpd_lock
.. doxygenfunction:: ehttpd_unlock
.. doxygenfunction:: ehttpd_set_cert_and_key
.. doxygenfunction:: ehttpd_set_client_validation
.. doxygenfunction:: ehttpd_add_client_cert
.. doxygenfunction:: ehttpd_shutdown

Structures
^^^^^^^^^^

.. doxygenstruct:: ehttpd_route_t
    :members:

.. doxygenstruct:: ehttpd_inst_t
    :members:

Type Definitions
^^^^^^^^^^^^^^^^

.. doxygentypedef:: ehttpd_route_handler_t
.. doxygentypedef:: ehttpd_recv_handler_t

Enumerations
^^^^^^^^^^^^

.. doxygenenum:: ehttpd_flags_t
