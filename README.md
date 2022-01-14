# cloudflare-dyndns2

cloudflare-dyndns2 is a [dyndns2](https://help.dyn.com/remote-access-api/perform-update/) API compatible server you can use in Cloudflare workers to update A/AAA records with generic dyndns2 clients like [ddclient](https://github.com/ddclient/ddclient), [python-dyndnsc](https://github.com/infothrill/python-dyndnsc) and many others (like your consumer router, potentially).

## Setup
You need a Cloudflare account (free plan is fine) with a domain configured and two [API tokens](https://dash.cloudflare.com/profile/api-tokens) created:
* **CF_ZONE_API_TOKEN**: With _Zone_ / _Zone_ / _Read_ permissions, scoped to all your zones.
* **CF_DNS_API_TOKEN**: With _Zone_ / _DNS_ / _Edit_ permissions, scoped to the domain you want to update.

To set up cloudflare-dyndns2, follow the [Cloudflare Workers: Get started guide](https://developers.cloudflare.com/workers/get-started/guide) until you have a logged in [wrangler](https://developers.cloudflare.com/workers/tooling/wrangler) config.

* Run `wrangler whoami` to get your _Account ID_
* Copy `wrangler.toml.tmpl` to `wrangler.toml`
* Add your _Account ID_ to `wrangler.toml`
* Choose a username and it to the `BASIC_USER` variable in `wrangler.toml`

Now add the tree required secrets using `wrangler`:
```bash
# A password of your choosing
wrangler secret put BASIC_PASS
# The Cloudflare API tokens you created
wrangler secret put CF_ZONE_API_TOKEN
wrangler secret put CF_DNS_API_TOKEN
```

After that you can publish the code by calling:
```bash
wrangler publish
```

You now need to create the A/AAAA records you want to update with your desired settings via the Cloudflare UI (or API). cloudflare-dyndns2 will only update existing records and won't create new ones.

## Client configuration

There are two routes that currently do the same thing, `/nic/update` and `/v3/update`. For details, please see: https://help.dyn.com/remote-access-api/perform-update

Currently, only the parameters `hostname` and `myip` are supported (in addition to a `json` parameter that makes the API return JSON instead of dyndns2 compatible responses).
Multiple hostnames, as well as IPv4 and IPv6 are supported (separated by comma). If multiple IPs of the same type are provided, only the first one is used.

Update URLs:
* `https://<worker-fqdn>/v3/update?hostname=<your-fqdn1>,<your-fqdn2>&myip=<ipv4>,<ipv6>`
* `https://<worker-fqdn>/nic/update?hostname=<your-fqdn1>,<your-fqdn2>&myip=<ipv4>,<ipv6>`

A ddclient config for IPv6 might look something like:
```conf
protocol=dyndns2
usev6=if, if=eth0
ssl=yes
server=<worker-fqdn>
login=<BASIC_USER>
password='<BASIC_PASS>'
<your-fqdn>
```