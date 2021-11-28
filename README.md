# OIDC Discovery client

This package covers two needs:

1. Get the discovery document from some authority
2. Get certificates from that authority

## Usage

`go
package main

import (
... your important stuff
"github.com/klyngen/golang-oidc-discovery"
)

func main() {
client, \_ := new oidcdiscovery.NewOidcDiscoveryClient("https://your-oidc-provider.com")

    // Now that you have all the good stuff you can do whatever you want

    // Getting certificates is really easy
    publicKeys, _ := client.GetCertificates();

    // This method returns the certificate with BEGIN and END
    publicKeys[0].GetCertificate();

    // Property of the struct and is without the BEGIN and END
    publicKeys[0].Key;

}
`

Happy hacking
