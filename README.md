# certbot-dns-nicru

NICru DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the nic.ru Remote API.

# Installation

```bash
pip install certbot-dns-nicrus
```


# Named Arguments

To start using DNS authentication for nicru, pass the following arguments on
certbot's command line:

|||
|--|--|
|``--authenticator dns-nicru`` | nicru config INI file. (Required) |
|``--dns-nicru-propagation-seconds <second>`` | waiting time for DNS to propagate before asking |


# Credentials

An example ``credentials.ini`` file:

```ini
dns_nicru_client_id = application-id
dns_nicru_client_secret = application-token
dns_nicru_username = 0001110/NIC-D
dns_nicru_password = password

dns_nicru_scope = .+:.+/zones/example.com(/.+)?

dns_nicru_service = DNS_SERVICE_NAME
dns_nicru_zone = example.com
```

The path to this file can be provided interactively or using the
``--dns-nicru-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should protect these API credentials as you would the
password to your ispconfig account. Users who can read this file can use these
credentials to issue arbitrary API calls on your behalf. Users who can cause
Certbot to run using these credentials can complete a ``dns-01`` challenge to
acquire new certificates or revoke existing certificates for associated
domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


## Examples

To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 900 seconds for DNS propagation:

```bash
certbot certonly \
    --authenticator dns-nicru \
    --dns-nicru-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
    --dns-nicru-propagation-seconds 300 \
    --server https://acme-v02.api.letsencrypt.org/directory \
    --agree-tos \
    --rsa-key-size 4096 \
    -d 'example.com' \
    -d '*.example.com'
```

# Docker


In order to create a docker container with a certbot-dns-ispconfig installation,
create an empty directory with the following ``Dockerfile``:

```docker
FROM certbot/certbot
RUN pip install certbot-dns-nicru
```

Proceed to build the image:
```bash
docker build -t certbot/dns-nicru .
```

Once that's finished, the application can be run as follows:
```
docker run --rm \
    -v /var/lib/letsencrypt:/var/lib/letsencrypt \
    -v /etc/letsencrypt:/etc/letsencrypt \
    --cap-drop=all \
    certbot/dns-nicru certonly \
    --authenticator dns-nicru \
    --dns-nicru-propagation-seconds 300 \
    --dns-nicru-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
    --no-self-upgrade \
    --keep-until-expiring --non-interactive --expand \
    --server https://acme-v02.api.letsencrypt.org/directory \
    -d example.com -d '*.example.com'
```

It is suggested to secure the folder as follows:
```bash
chown root:root /etc/letsencrypt/.secrets
chmod 600 /etc/letsencrypt/.secrets
```
