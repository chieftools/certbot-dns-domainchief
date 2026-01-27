"""
The `~certbot_dns_domainchief.dns_domainchief` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Domain Chief_ API.

.. _Domain Chief: https://domain.chief.app?ref=certbot-dns-domainchief

.. note::
   The plugin is not installed by default.

Installation
------------

If you followed the official instructions, you likely installed certbot as a
snap. In that case, you can install the plugin by running:

.. code:: bash

    snap install certbot-dns-domainchief
    snap set certbot trust-plugin-with-root=ok
    snap connect certbot:plugin certbot-dns-domainchief

Alternatively, you can install certbot using pip and install the plugin by
running:

.. code:: bash

    pip install certbot-dns-domainchief

Named Arguments
---------------

========================================  =====================================
``--dns-domainchief-credentials``         Domain Chief credentials_ INI file. (Required)
``--dns-domainchief-propagation-seconds`` The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record. (Default: 60)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing Domain Chief API
credentials, obtained from your
`Domain Chief account <https://domain.chief.app/api/tokens>`_.

Domain Chief credentials are not scoped and give access to all account features.

.. code-block:: ini
   :name: certbot_domainchief_credentials.ini
   :caption: Example credentials file:

    # Domain Chief API credentials used by Certbot
    dns_domainchief_api_key = ctp_...

The path to this file can be provided interactively or using the
``--dns-domainchief-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Domain Chief account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --authenticator dns-domainchief \\
     --dns-domainchief-credentials ~/.secrets/certbot/domainchief.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --authenticator dns-domainchief \\
     --dns-domainchief-credentials ~/.secrets/certbot/domainchief.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 120 seconds
             for DNS propagation

   certbot certonly \\
     --authenticator dns-domainchief \\
     --dns-domainchief-credentials ~/.secrets/certbot/domainchief.ini \\
     --dns-domainchief-propagation-seconds 120 \\
     -d example.com

"""
