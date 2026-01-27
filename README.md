# [Certbot](https://certbot.eff.org/) [Domain Chief](https://domain.chief.app?ref=certbot-dns-domainchief) plugin

[![Snap Store Badge](https://snapcraft.io/certbot-dns-domainchief/badge.svg?version=latest)](https://snapcraft.io/certbot-dns-domainchief)
[![PyPI Version Badge](https://img.shields.io/pypi/v/certbot-dns-domainchief)](https://pypi.org/project/certbot-dns-domainchief/)

This plugin enables DNS verification with [Certbot](https://certbot.eff.org/) when using [Domain Chief](https://domain.chief.app?ref=certbot-dns-domainchief).

## Installation

If you installed certbot as a snap, then you have to install this plugin as a snap as well:

```bash
snap install certbot-dns-domainchief
snap set certbot trust-plugin-with-root=ok
snap connect certbot:plugin certbot-dns-domainchief
```

and can be upgraded using the `refresh` command:

```bash
snap refresh certbot-dns-domainchief
```

Alternatively this package can be installed with pip:

```bash
pip install certbot-dns-domainchief
```

and can be upgraded using the `--upgrade` flag

```bash
pip install --upgrade certbot-dns-domainchief
```

## Credentials

You need to supply Certbot with a Domain Chief API key, this is an example of how a credentials file can look:

```ini
# Domain Chief API credentials used by Certbot
dns_domainchief_api_key = ctp_...
```

You can create a new API key [here](https://domain.chief.app/api/token/create?ref=certbot-dns-domainchief), ensure it has the `domainchief` scope and has the correct team selected.

Keep in mind that the credentials file should be readable only by the user running Certbot and the credentials cannot be scoped, so they can be used to perform any action on your behalf if compromised.

## Examples

Simple example for a single domain:

```bash
certbot certonly \
  --authenticator dns-domainchief \
  --dns-domainchief-credentials ~/.secrets/domainchief.ini \
  -d example.com
```

Simple example for wildcard domain:

```bash
certbot certonly \
  --authenticator dns-domainchief \
  --dns-domainchief-credentials ~/.secrets/domainchief.ini \
  -d example.com \
  -d *.example.com
```

Example changing the propagation delay, although you should not have to
adjust it normally:

```bash
certbot certonly \
  --authenticator dns-domainchief \
  --dns-domainchief-credentials ~/.secrets/domainchief.ini \
  --dns-domainchief-propagation-seconds 120 \
  -d example.com
```

## Security Vulnerabilities

If you discover a security vulnerability, please send an e-mail to us at `hello@chief.app`. All security vulnerabilities will be swiftly addressed.
