# Documentation

## Description

Quick Java library to perform A and AAAA DNS queries over HTTPS to 1.1.1.1, and get a HttpsURLConnection or an SSLSocket where the domain name of the server is indicated via SNI (and the hostname is the resolved ip address).

## Usage for quick DNS-over-HTTPS queries only

```java
Doh client = new Doh();
List<String> ipv4Results = client.resIPv4(domainName);
List<String> ipv6Results = client.resIPv6(domainName);
```

## Getting an HttpsURLConnection (DNS-over-HTTPS is used to resolve the domain name)

```java
// If omitted or true, an AAAA DNS request is sent first, and the first returned IPv6 is used.
// If false, or no IPv6 is available according to the DNS response, an A DNS request is sent, and the first returned IPv4 is used.
boolean preferIPv6IfAvailable = false;
HttpsURLConnection connection = HttpsConnectionWithDoH.connectAfterResolvingViaDoH(<domain-name-here>, <subresource-here>, preferIPv6IfAvailable);
```

## Getting an SSLSocket (DNS-over-HTTPS is used to resolve the domain name)

```java
// If omitted or true, an AAAA DNS request is sent first, and the first returned IPv6 is used.
// If false, or no IPv6 is available according to the DNS response, an A DNS request is sent, and the first returned IPv4 is used.
boolean preferIPv6IfAvailable = false;
SSLSocket socket = TLSSocketWithDoH.connect(domainName, 443, preferIPv6IfAvailable);
```
