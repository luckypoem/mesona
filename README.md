# mesona

A TLS MITM proxy using GnuTLS's length hiding capability that adds additional record padding to mitigate length-based analysis against TLS streams.

## Usage

Edit `configuration.py` under directory `mesona` for configuration and run module `mesona.proxy`.
```
python -m mesona.proxy
```

## Dependencies

* Python 2.7
* [GnuTLS](https://gnutls.org/)
* [python-gnutls](https://github.com/nametoolong/python-gnutls)
* [PySocks](https://github.com/Anorov/PySocks) (only needed when proxy is set)

Unfortunately python-gnutls does not support Python 3, so Python 2.7 is required.

## Configuration

The Python script `configuration.py` is directly `import`ed as the configuration. Each key-value pair in dictionary `settings` declares a proxy instance and `default_settings` is the default value of settings for a proxy instance.

Key in `settings` should be the server address although it is currently ignored. Refer to the documentation of python-gnutls for usage of `X509Certificate`, `X509Credentials`, `X509CRL` and `X509PrivateKey`.
