from gnutls.crypto import X509Certificate, X509CRL, X509PrivateKey
from gnutls.connection import X509Credentials

empty_credential = X509Credentials()

# Default settings for what is undeclared.
default_settings = {
    "credentials_as_server": empty_credential,
    "credentials_as_client": empty_credential,
    "server_name_indicator": None,
    "priority_string_as_server": "NORMAL",
    "priority_string_as_client": "NORMAL",
    "use_length_hiding_with_server": False,
    "use_length_hiding_with_client": False,
    "padding_range_with_server": (0, 0),
    "padding_range_with_client": (0, 0),
    "buffer_size": 1024,
    "verify_server_identity": False,
    "verify_client_identity": False,
    "suppress_exceptions": False
}

# The main configuration.
# Each key-value pair declares a proxy instance.
settings = {
    # the key should be the server address (currently ignored) and the value must be a dictionary
    ("127.0.0.1", 39956): {
        # the address we should forward connections to
        "server_address": ("127.0.0.1", 39956),

        # the address we should be listening at
        "listen_address": ("0.0.0.0", 40056),

        # our credentials as a TLS server (when talking to our clients)
        "credentials_as_server": X509Credentials(X509Certificate(open("certs/cert.crt").read()), X509PrivateKey(open("certs/key.key").read())),

        # our credentials as a TLS client (when talking to the upstream server)
        "credentials_as_client": empty_credential,

        # the SNI to be sent to the upstream server
        "server_name_indicator": None,

        # the GnuTLS priority string as a TLS server (when talking to our clients)
        "priority_string_as_server": "NORMAL",

        # the GnuTLS priority string as a TLS client (when talking to the upstream server)
        "priority_string_as_client": '''
NONE:
+VERS-TLS1.2:
+VERS-TLS1.1:
+VERS-TLS1.0:
+AES-128-CBC:
+AES-256-CBC:
+SHA256:
+SHA1:
+RSA:
+ECDHE-RSA:
+ECDHE-ECDSA:
+DHE-DSS:
+SIGN-RSA-SHA256:
+SIGN-RSA-SHA384:
+SIGN-RSA-SHA1:
+SIGN-ECDSA-SHA256:
+SIGN-ECDSA-SHA384:
+SIGN-ECDSA-SHA1:
+SIGN-DSA-SHA1:
+GROUP-SECP256R1:
+GROUP-SECP384R1:
+CTYPE-X509:
%NO_TICKETS:
%SAFE_RENEGOTIATION:
%NO_ETM:
%LATEST_RECORD_VERSION
'''.replace('\n', '').strip(),

        # whether to use length hiding when talking to the upstream server
        "use_length_hiding_with_server": True,

        # whether to use length hiding when talking to our clients
        "use_length_hiding_with_client": False,

        # the range of padding when talking to the upstream server, if use_length_hiding_with_server is True
        # the first element of the tuple must be negative or zero
        # the second element must be positive or zero
        "padding_range_with_server": (-64, 512),

        # the range of padding when talking to our clients, if use_length_hiding_with_client is True
        "padding_range_with_client": (0, 0),

        # the size of the buffer
        "buffer_size": 1024,

        # whether to verify upstream server's identity
        "verify_server_identity": False,

        # whether to verify our client's identity
        "verify_client_identity": False,

        # whether to suppress exceptions during processing of request
        # note that those exceptions are really annoying
        "suppress_exceptions": True

        # in case you needed to use a proxy
        # "proxy": ("HTTP", "127.0.0.1", 1080)
        # "proxy": ("SOCKS4", "127.0.0.1", 1080)
        # "proxy": ("SOCKS5", "127.0.0.1", 1080)
    },

    ("example.org", 443): {
        "server_address": ("example.org", 443),
        "listen_address": ('0.0.0.0', 443),
        "credentials_as_server": X509Credentials(X509Certificate(open("certs/cert.crt").read()), X509PrivateKey(open("certs/key.key").read())),
        "credentials_as_client": X509Credentials(trusted=[X509Certificate(open("certs/ca.crt").read())]),
        "server_name_indicator": "example.org",
        "priority_string_as_server": '''
NONE:
+VERS-TLS1.2:
+VERS-TLS1.1:
+VERS-TLS1.0:
+AES-128-CBC:
+AES-256-CBC:
+SHA256:
+SHA1:
+RSA:
+ECDHE-RSA:
+ECDHE-ECDSA:
+DHE-DSS:
+SIGN-RSA-SHA256:
+SIGN-RSA-SHA384:
+SIGN-RSA-SHA1:
+SIGN-ECDSA-SHA256:
+SIGN-ECDSA-SHA384:
+SIGN-ECDSA-SHA1:
+SIGN-DSA-SHA1:
+GROUP-SECP256R1:
+GROUP-SECP384R1:
+CTYPE-X509:
%NO_TICKETS:
%SAFE_RENEGOTIATION:
%NO_ETM:
%LATEST_RECORD_VERSION
'''.replace('\n', '').strip(),
        "priority_string_as_client": "SECURE128",
        "use_length_hiding_with_server": False,
        "use_length_hiding_with_client": True,
        "padding_range_with_server": (0, 0),
        "padding_range_with_client": (-128, 256),
        "buffer_size": 4096,
        "verify_server_identity": True,
        "verify_client_identity": False,
        "suppress_exceptions": True
    }
}
