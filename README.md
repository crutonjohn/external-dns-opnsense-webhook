# ExternalDNS Webhook Provider for OPNsense

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/crutonjohn/external-dns-opnsense-webhook?style=for-the-badge)](https://github.com/opnsense/external-dns-opnsense-webhook/releases)&nbsp;&nbsp;
[![Discord](https://img.shields.io/discord/673534664354430999?style=for-the-badge&label&logo=discord&logoColor=white&color=blue)](https://discord.gg/home-operations)

</div>

This webhook graciously ~~stolen~~ inspired by [Kashall's Unifi Webhook](https://github.com/kashalls/external-dns-unifi-webhook).

> [!WARNING]
> This software is experimental and **NOT FIT FOR PRODUCTION USE!**

[ExternalDNS](https://github.com/kubernetes-sigs/external-dns) is a Kubernetes add-on for automatically managing DNS records for Kubernetes ingresses and services by using different DNS providers. This webhook provider allows you to automate DNS records from your Kubernetes clusters into your OPNsense Firewall's Unbound or dnsmasq service.

## 🗒️ Important Notes

### Choosing a DNS Plugin

The webhook talks to one OPNsense DNS plugin at a time, selected with the `OPNSENSE_PLUGIN` environment variable:

| `OPNSENSE_PLUGIN` | OPNsense service | Supported record types |
| ----------------- | ---------------- | ---------------------- |
| `unbound` (default) | Unbound DNS | A, AAAA, TXT, CNAME |
| `dnsmasq` | Dnsmasq DNS & DHCP | A, AAAA, CNAME |

If `OPNSENSE_PLUGIN` is unset the webhook defaults to `unbound`, matching the behavior of earlier releases.

Record types a plugin cannot represent are logged and skipped rather than failing the sync, so pointing ExternalDNS at the dnsmasq backend with `registry: txt` will not work — use `registry: noop`, or the Unbound backend.

### Unbound

A, AAAA, and TXT records map 1:1 with Unbound's Host Overrides. CNAME records are stored as Host Override Aliases.

Because an Alias references its target by internal ID rather than by name, **a CNAME can only be created if its target exists as an A or AAAA record in Unbound**. When the target is part of the same batch of changes it is created first, so this is usually transparent. A CNAME whose target is not present in Unbound at all cannot be represented, and the sync will fail with an error naming the missing target.

> [!NOTE]
> TXT record support requires OPNsense >= 25.7 or later versions with TXT record support in Unbound.

### Dnsmasq

A and AAAA records map to dnsmasq's host entries. TXT records have no representation here and are skipped with a warning.

CNAME records are stored in the `CNAME records` field of the host entry they point at, which OPNsense renders into `dnsmasq.conf` as a `cname=` directive. They are not records in their own right, so **a CNAME can only be created if its target exists as an A or AAAA host entry**, exactly as on Unbound. Creating or removing one rewrites that field on the target entry and leaves the rest of the entry untouched.

Two consequences worth knowing:

- Repointing a CNAME at a different target moves it between entries, so it is briefly absent from both. ExternalDNS reconciles this on the next sync.
- Deleting the host entry that a CNAME hangs off deletes the CNAME with it, because it is stored as part of that entry.

> [!NOTE]
> CNAME support on this backend requires OPNsense >= 25.7, which is when the `CNAME records` field was added to dnsmasq host entries. On 25.1.x the field does not exist and CNAMEs will silently fail to apply, so ExternalDNS will retry them on every sync.

### Structuring Your Unbound Records

> [!WARNING]
> If you don't follow this **manually entered A/AAAA records can be permanently destroyed**

If you have records that are managed manually or by some process other than this webhook and you intend for those records to share a domain, then you must structure them in a way that avoids conflict.

The webhook examines all records defined in Host Overrides **and all Host Aliases**. Anything matching your domain filter is treated as managed, so an Alias in a filtered domain is not a safe place to keep a manually maintained record — earlier versions of this webhook ignored Aliases, but they are now read as CNAME records.

To avoid ownership conflicts, keep manually managed records in a domain the webhook's domain filter does not cover.

For example:

- You run the webhook with the domain filter set for `example.com`
- You have manually created a Host Override for `host1.example.com` in OPNSense's Unbound Web UI pointed to `192.168.10.2`.

You will need to either:

- Move that record to a domain outside the filter, such as `host1.internal.example.net`, or
- Narrow the webhook's `domainFilters` so it does not cover the records you maintain by hand

Another option would be to create `dnsendpoint` CRDs for all the records you need in Unbound and let the webhook manage everything.

## 🎯 Requirements

- ExternalDNS >= v0.14.0
- OPNsense >= 23.7.12_5
- Unbound >= 1.19.0 (when using `OPNSENSE_PLUGIN=unbound`)
- OPNsense >= 25.7 (when using `OPNSENSE_PLUGIN=dnsmasq`)

> [!NOTE]
> The dnsmasq backend needs the MVC host endpoints (`api/dnsmasq/settings/searchHost`, `addHost`, `setHost` and `delHost`), added in OPNsense 25.1.2, and the `cnames` field on host entries, added in 25.7. A and AAAA records therefore work from 25.1.2 onwards, but 25.7 is required for CNAME support. Earlier 25.1 releases only ship the legacy dnsmasq UI and will return 404 for these calls.

## ⚙️ Configuration

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `OPNSENSE_HOST` | yes | — | Base URL of your OPNsense firewall, e.g. `https://192.168.1.1` |
| `OPNSENSE_API_KEY` | yes | — | API key for the user created below |
| `OPNSENSE_API_SECRET` | yes | — | API secret for that key |
| `OPNSENSE_PLUGIN` | no | `unbound` | DNS plugin to manage: `unbound` or `dnsmasq` |
| `OPNSENSE_SKIP_TLS_VERIFY` | no | `true` | Skip TLS certificate verification against the firewall |
| `LOG_LEVEL` | no | `info` | Log verbosity, e.g. `debug` |

## ⛵ Deployment

1. Create a local user with a password in your OPNsense firewall. `System > Access > Users`

2. Create an API keypair for the user you created in step 1.

3. Create (or use an existing) group to limit your user's permissions. For the Unbound backend the known required privileges are:
- `Services: Unbound DNS: Edit Host and Domain Override`
- `Services: Unbound (MVC)`
- `Status: DNS Overview`

    The first of these already covers the Host Alias endpoints, so CNAME support needs no additional privilege.

    For the dnsmasq backend, grant `Services: Dnsmasq DNS/DHCP: Settings` instead. It maps to `api/dnsmasq/*`, which covers every call the webhook makes on this backend, so it is the only privilege required. On OPNsense 25.1.2 through 25.1.5 the same privilege is listed under its older name, `Services: Dnsmasq DNS: Settings`.

4. Add the ExternalDNS Helm repository to your cluster.

    ```sh
    helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
    ```

5. Create a Kubernetes secret called `external-dns-opnsense-secret` that holds `api_key` and `api_secret` with their respective values from step 1:

    ```yaml
    apiVersion: v1
    stringData:
      api_secret: <INSERT API SECRET>
      api_key: <INSERT API KEY>
    kind: Secret
    metadata:
      name: external-dns-opnsense-secret
    type: Opaque
    ```

6. Create the helm values file, for example `external-dns-webhook-values.yaml`:

    ```yaml
    fullnameOverride: external-dns-opnsense
    logLevel: debug
    provider:
      name: webhook
      webhook:
        image:
          repository: ghcr.io/crutonjohn/external-dns-opnsense-webhook
          tag: main # replace with a versioned release tag
        env:
          - name: OPNSENSE_API_SECRET
            valueFrom:
              secretKeyRef:
                name: external-dns-opnsense-secret
                key: api_secret
          - name: OPNSENSE_API_KEY
            valueFrom:
              secretKeyRef:
                name: external-dns-opnsense-secret
                key: api_key
          - name: OPNSENSE_HOST
            value: https://192.168.1.1 # replace with the address to your OPNsense router
          - name: OPNSENSE_PLUGIN
            value: unbound # "unbound" (default) or "dnsmasq"
          - name: OPNSENSE_SKIP_TLS_VERIFY
            value: "true" # optional depending on your environment
          - name: LOG_LEVEL
            value: debug
        livenessProbe:
          httpGet:
            path: /healthz
            port: http-wh-metrics
          initialDelaySeconds: 10
          timeoutSeconds: 5
        readinessProbe:
          httpGet:
            path: /readyz
            port: http-wh-metrics
          initialDelaySeconds: 10
          timeoutSeconds: 5
    extraArgs:
      - --ignore-ingress-tls-spec
    policy: sync
    sources: ["ingress", "service", "crd"]
    registry: noop
    domainFilters: ["example.com"] # replace with your domain
    ```

7. Install the Helm chart

    ```sh
    helm install external-dns-opnsense external-dns/external-dns -f external-dns-opnsense-values yaml --version 1.14.3 -n external-dns
    ```

---

## 👷 Building & Testing

Build:

```sh
go build -ldflags "-s -w -X main.Version=test -X main.Gitsha=test" ./cmd/webhook
```

Test:

```sh
go test ./...
```

There is also an optional suite that runs against a real OPNsense firewall, excluded from normal builds and from CI by the `live` build tag. It skips unless `OPNSENSE_HOST` and credentials are set.

```sh
# Read-only: reports the wire shape of the search response and the record counts
go test -tags=live ./internal/opnsense/ -run TestLiveInspect -v
```

The round-trip test creates and deletes records and so needs an explicit scratch domain. It refuses to run if any name it would use already exists, and restores the firewall afterwards. Set `LIVE_RECONFIGURE=1` to also reload dnsmasq at the end.

```sh
LIVE_WRITE_DOMAIN=scratch.example.com \
  go test -tags=live ./internal/opnsense/ -run TestLiveRoundTrip -v
```

Run:

```sh
OPNSENSE_HOST=https://192.168.0.1 OPNSENSE_API_SECRET=<secret value> OPNSENSE_API_KEY=<key value> ./webhook
```

To target dnsmasq instead of Unbound, add `OPNSENSE_PLUGIN=dnsmasq`:

```sh
OPNSENSE_HOST=https://192.168.0.1 OPNSENSE_API_SECRET=<secret value> OPNSENSE_API_KEY=<key value> OPNSENSE_PLUGIN=dnsmasq ./webhook
```

---

## 🤝 Gratitude and Thanks

Thanks to all the people who donate their time to the [Home Operations](https://discord.gg/home-operations) Discord community.

I'd like to thank the following people for answering my hare-brained questions:
- @kashalls
- @onedr0p
- @uhthomas
- @tyzbit
- @buroa
