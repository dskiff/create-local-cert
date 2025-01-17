# create-local-cert

Simple, minimal CA + server cert generation.

## How?

```
create-local-cert \
    --out <destination folder> \
    --name-constraints <whether CA should be constrained to listed domains> \
    <domain 1> <domain 2> ...
```

Example:
```
create-local-cert horrible-iot-infra.lan secondary-domain.home
```

This:
  - Creates a CA 
    - valid for 10 years
    - only valid for signing certs for `horrible-iot-infra.lan` and `secondary-domain.home` (using the Name Constraints extension)
  - Creates a server certificate
    - valid for 10 years
    - common name of `horrible-iot-infra.lan`
    - SANs of `horrible-iot-infra.lan` + `secondary-domain.home`
    - Signed by CA
  - Writes PEM files to: `./certs` (`ca.key`, `ca.crt`, `server.key`, `server.crt`)

## Why?

I've often gone to use a tool, and found that I need to provide certs. While let's encrypt et al are much better options, sometimes they aren't viable. 

I've seen some other tools, but I haven't seen one that scratched my itch. They're either overly complicated (and I feel like I'd be better off just using openssl), require root (e.g. `mkcert`), and/or do not support CA Name Constraints (which aren't perfect, but can substantially limit the blast radius of a lost key).

## Should I use this?

First, if you can use a valid domain + a valid cert (they're free!), you'll likely be better suited doing so. You won't have to sync your trust stores. You won't have to worry about domain squatting. You don't have to worry about your CA private key being leaked, and arbitrary domains being compromised.

Second, I offer no warranty, etc, etc. I made this because I wanted it, and if it helps you, great! However, integrity of your trust store is important. If you trust a CA, and a bad actor has access to that CA's private key, they could sign a key for any domain the CA is able to. Doing the CA + CSR dance in openssl isn't terrible, and I personally trust openssl more than a quick hack I made.

I repeat, trusting arbitrary CAs is DANGEROUS! Do not use them unless you have to, know what you're doing, and are willing to accept all of the potential consequences.

If that's you, then by all means, enjoy!

## Can I make this do x?

I am open to PRs (especially for bug fixes). However, I do want to keep this small and simple. You are also certainly welcome to fork this.

