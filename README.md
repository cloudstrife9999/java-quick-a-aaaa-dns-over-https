# Documentation

## Description

Quick Java library to perform A and AAAA DNS queries over HTTPS to 1.1.1.1 .

Also, quick Java Library to get an HttpsUrlConnection where the domain resolution is done via DNS-over-HTTPS.

## Usage for quick DNS-over-HTTPS queries

```java
Doh client = new Doh();
List<String> ipv4Results = client.resIPv4(domainName);
List<String> ipv6Results = client.resIPv6(domainName);
```

## Getting a HttpsUrlConnection (DNS-over-HTTPS is used to resolve the domain name)

```java
// If omitted or true, an AAAA DNS request is sent first, and the first returned IPv6 is used.
// If false, or no IPv6 is available according to the DNS response, an A DNS request is sent, and the first returned IPv4 is used.
boolean preferIPv6 = false;
HttpsURLConnection connection = HttpsConnectionWithDoH.connectAfterResolvingViaDoH(<domain-name-here>, <subresource-here>, preferIPv6);
```
