accessregister
==============

A registration interface for I2P service tunnels

This is a prototype of a sort of "Compound" tunnel type. It uses two tunnels,
together, to provide private access to a service via a public registration
interface. In it's current form, the private service and the public registration
interface have different addresses, and I'm pretty sure that is a requirement.
The *point* is to use this registration tunnel to add, remove, administer, and
track i2ptunnl access list members as a form of "login" for services like VPN's
and outproxies especially.

This implementation of an Access Register i2ptunnel in Go is "composed" of a
```samtunnel.SAMTunnel```, which is a generic interface that can be used like
any i2ptunnel and a ```samforwarder.SAMForwarder``` running with as an
```httpserver``` which emulates the functionality of an i2ptunnel HTTP Server
tunnel.
