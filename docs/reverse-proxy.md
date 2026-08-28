# HTTPS reverse proxy

Bind Watchpost to loopback and let Caddy or nginx own public TLS. Start it with
`--secure-cookies` (or `WATCHPOST_SECURE_COOKIES=1`) so session cookies remain
Secure after TLS terminates at the proxy. Do not expose port 8080 publicly.

## Caddy

```caddyfile
watchpost.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## nginx

```nginx
server {
    listen 443 ssl http2;
    server_name watchpost.example.com;
    ssl_certificate /etc/letsencrypt/live/watchpost.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/watchpost.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
```

Watchpost deliberately does not trust forwarded client-IP or scheme headers for
authorization. Restrict direct backend access with loopback binding and host
firewall policy.
