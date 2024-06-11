# ExternalDNS Webhook Provider for OPNsense

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/crutonjohn/external-dns-opnsense-webhook?style=for-the-badge)](https://github.com/opnsense/external-dns-opnsense-webhook/releases)&nbsp;&nbsp;
[![Discord](https://img.shields.io/discord/673534664354430999?style=for-the-badge&label&logo=discord&logoColor=white&color=blue)](https://discord.gg/home-operations)

</div>

This webhook graciously ~~stolen~~ inspired by [Kashall's Unifi Webhook](https://github.com/kashalls/external-dns-unifi-webhook).

> [!WARNING]
> This software is experimental and **NOT FIT FOR PRODUCTION USE!**

[ExternalDNS](https://github.com/kubernetes-sigs/external-dns) is a Kubernetes add-on for automatically managing DNS records for Kubernetes ingresses and services by using different DNS providers. This webhook provider allows you to automate DNS records from your Kubernetes clusters into your OPNsense Firewall's Unbound service.

## 🗒️ Important Notes

As of this writing this webhook only supports creating A records using Unbound's Host Overrides. Theoretically AAAA records should work without much (if any) modification. A/AAAA records work because they effectively map 1:1 with Host Overrides. With significantly more effort, CNAMEs could be supported and mapped to Host Override Aliases, which I may or may not implement.

Furthermore, due to lack of support for TXT records in OPNsense's Unbound API we cannot leverage external-dns' normal `registry` behavior. Using an external registry would be optimal but not required for this webhook to function. Without a valid registry there is no concept of DNS record "ownership". **This means that the webhook will assume ownership of all Host Overrides that match `domainFilters` in Unbound**. There is a DNS pattern that exists to overcome this limitation detailed below.

### Structuring Your Unbound Records

> [!WARNING]
> If you don't follow this **manually entered A/AAAA records can be permanently destroyed**

If you have records that are managed manually or by some process other than this webhook and you intend for those records to share a domain, then you must structure them in a way that avoids conflict. The webhook examines all records defined in Host Overrides but does **not** evaluate any Aliases. To avoid ownership conflicts you should create a "stub" Host Override pointing to your intended IP address, then create aliases that use your desired domain.

For example:

- You run the webhook with the domain filter set for `example.com`
- You have manually created a Host Override for `host1.example.com` in OPNSense's Unbound Web UI pointed to `192.168.10.2`.

You will need to:
- Create a new Host Override with a different domain such as `host1.fake.com` pointing to `192.168.10.2`
- Create an Alias under `host1.fake.com` that uses the original domain like `host1.example.com`

This effecively protects your record from ownership conflicts while still allowing you to define custom records for a domain used by this webhook. Another option would be to create `dnsendpoint` CRDs for all the records you need in Unbound and let the webhook manage everything.

## 🎯 Requirements

- ExternalDNS >= v0.14.0
- OPNsense >= 23.7.12_5
- Unbound >= 1.19.0

## ⛵ Deployment

1. Create a local user with a password in your OPNsense firewall. `System > Access > Users`

2. Create an API keypair for the user you created in step 1.

3. Create (or use an existing) group to limit your user's permissions. The known required privileges are:
- `Services: Unbound DNS: Edit Host and Domain Override`
- `Services: Unbound (MVC)`
- `Status: DNS Overview`

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

## 🤝 Gratitude and Thanks

Thanks to all the people who donate their time to the [Home Operations](https://discord.gg/home-operations) Discord community.

I'd like to thank the following people for answering my hare-brained questions:
- @kashalls
- @onedr0p
- @uhthomas
- @tyzbit
- @buroa
