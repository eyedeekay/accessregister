package accessregister

import (
	"fmt"
	"strconv"
)

//Option is a AccessTunnel Option
type Option func(*AccessTunnel) error

//SetFilePath sets the path to save the config file at.
func SetFilePath(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().FilePath = s
		c.SAMForwarder.Config().FilePath = "registrar." + s
		return nil
	}
}

//SetType sets the type of the forwarder server
func SetType(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if s == "http" {
			c.SAMTunnel.Config().Type = s
			c.SAMForwarder.Config().Type = "httpserver"
			return nil
		} else {
			c.SAMTunnel.Config().Type = "server"
			c.SAMForwarder.Config().Type = "httpserver"
			return nil
		}
	}
}

//SetSigType sets the type of the forwarder server
func SetSigType(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if s == "" {
			c.SAMTunnel.Config().SigType = ""
		} else if s == "DSA_SHA1" {
			c.SAMTunnel.Config().SigType = "DSA_SHA1"
			c.SAMForwarder.Config().SigType = "DSA_SHA1"
		} else if s == "ECDSA_SHA256_P256" {
			c.SAMTunnel.Config().SigType = "ECDSA_SHA256_P256"
			c.SAMForwarder.Config().SigType = "ECDSA_SHA256_P256"
		} else if s == "ECDSA_SHA384_P384" {
			c.SAMTunnel.Config().SigType = "ECDSA_SHA384_P384"
			c.SAMForwarder.Config().SigType = "ECDSA_SHA384_P384"
		} else if s == "ECDSA_SHA512_P521" {
			c.SAMTunnel.Config().SigType = "ECDSA_SHA512_P521"
			c.SAMForwarder.Config().SigType = "ECDSA_SHA512_P521"
		} else if s == "EdDSA_SHA512_Ed25519" {
			c.SAMTunnel.Config().SigType = "EdDSA_SHA512_Ed25519"
			c.SAMForwarder.Config().SigType = "EdDSA_SHA512_Ed25519"
		} else {
			c.SAMTunnel.Config().SigType = "EdDSA_SHA512_Ed25519"
			c.SAMForwarder.Config().SigType = "EdDSA_SHA512_Ed25519"
		}
		return nil
	}
}

//SetSaveFile tells the router to save the tunnel's keys long-term
func SetSaveFile(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().SaveFile = b
		c.SAMForwarder.Config().SaveFile = b
		return nil
	}
}

//SetHost sets the host of the service to forward
func SetHost(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().TargetHost = s
		c.SAMForwarder.Config().TargetHost = s
		return nil
	}
}

//SetPort sets the port of the service to forward
func SetPort(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		port, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("Invalid TCP Server Target Port %s; non-number ", s)
		}
		if port < 65536 && port > -1 {
			c.SAMTunnel.Config().TargetPort = s
			return nil
		}
		return fmt.Errorf("Invalid port")
	}
}

//SetSAMHost sets the host of the AccessTunnel's SAM bridge
func SetSAMHost(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().SamHost = s
		c.SAMForwarder.Config().SamHost = s
		return nil
	}
}

//SetSAMPort sets the port of the AccessTunnel's SAM bridge using a string
func SetSAMPort(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		port, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("Invalid SAM Port %s; non-number", s)
		}
		if port < 65536 && port > -1 {
			c.SAMTunnel.Config().SamPort = s
			c.SAMForwarder.Config().SamPort = s
			return nil
		}
		return fmt.Errorf("Invalid port")
	}
}

//SetName sets the host of the AccessTunnel's SAM bridge
func SetName(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().TunName = s
		c.SAMForwarder.Config().TunName = s
		return nil
	}
}

//SetInLength sets the number of hops inbound
func SetInLength(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u < 7 && u >= 0 {
			c.SAMTunnel.Config().InLength = u
			c.SAMForwarder.Config().InLength = u
			return nil
		}
		return fmt.Errorf("Invalid inbound tunnel length")
	}
}

//SetOutLength sets the number of hops outbound
func SetOutLength(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u < 7 && u >= 0 {
			c.SAMTunnel.Config().OutLength = u
			c.SAMForwarder.Config().OutLength = u
			return nil
		}
		return fmt.Errorf("Invalid outbound tunnel length")
	}
}

//SetInVariance sets the variance of a number of hops inbound
func SetInVariance(i int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if i < 7 && i > -7 {
			c.SAMTunnel.Config().InVariance = i
			c.SAMForwarder.Config().InVariance = i
			return nil
		}
		return fmt.Errorf("Invalid inbound tunnel length")
	}
}

//SetOutVariance sets the variance of a number of hops outbound
func SetOutVariance(i int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if i < 7 && i > -7 {
			c.SAMTunnel.Config().OutVariance = i
			c.SAMForwarder.Config().OutVariance = i
			return nil
		}
		return fmt.Errorf("Invalid outbound tunnel variance")
	}
}

//SetInQuantity sets the inbound tunnel quantity
func SetInQuantity(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u <= 16 && u > 0 {
			c.SAMTunnel.Config().InQuantity = u
			c.SAMForwarder.Config().InQuantity = u
			return nil
		}
		return fmt.Errorf("Invalid inbound tunnel quantity")
	}
}

//SetOutQuantity sets the outbound tunnel quantity
func SetOutQuantity(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u <= 16 && u > 0 {
			c.SAMTunnel.Config().OutQuantity = u
			c.SAMForwarder.Config().OutQuantity = u
			return nil
		}
		return fmt.Errorf("Invalid outbound tunnel quantity")
	}
}

//SetInBackups sets the inbound tunnel backups
func SetInBackups(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u < 6 && u >= 0 {
			c.SAMTunnel.Config().InBackupQuantity = u
			c.SAMForwarder.Config().InBackupQuantity = u
			return nil
		}
		return fmt.Errorf("Invalid inbound tunnel backup quantity")
	}
}

//SetOutBackups sets the inbound tunnel backups
func SetOutBackups(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u < 6 && u >= 0 {
			c.SAMTunnel.Config().OutBackupQuantity = u
			c.SAMTunnel.Config().OutBackupQuantity = u
			return nil
		}
		return fmt.Errorf("Invalid outbound tunnel backup quantity")
	}
}

//SetEncrypt tells the router to use an encrypted leaseset
func SetEncrypt(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if b {
			c.SAMTunnel.Config().EncryptLeaseSet = true
			return nil
		}
		c.SAMTunnel.Config().EncryptLeaseSet = false
		return nil
	}
}

//SetLeaseSetKey sets the host of the AccessTunnel's SAM bridge
func SetLeaseSetKey(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().LeaseSetKey = s
		return nil
	}
}

//SetLeaseSetPrivateKey sets the host of the AccessTunnel's SAM bridge
func SetLeaseSetPrivateKey(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().LeaseSetPrivateKey = s
		return nil
	}
}

//SetLeaseSetPrivateSigningKey sets the host of the AccessTunnel's SAM bridge
func SetLeaseSetPrivateSigningKey(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().LeaseSetPrivateSigningKey = s
		return nil
	}
}

//SetMessageReliability sets the host of the AccessTunnel's SAM bridge
func SetMessageReliability(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().MessageReliability = s
		c.SAMTunnel.Config().MessageReliability = s
		return nil
	}
}

//SetAllowZeroIn tells the tunnel to accept zero-hop peers
func SetAllowZeroIn(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().InAllowZeroHop = b
		c.SAMForwarder.Config().InAllowZeroHop = b
		return nil
	}
}

//SetAllowZeroOut tells the tunnel to accept zero-hop peers
func SetAllowZeroOut(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().OutAllowZeroHop = b
		c.SAMTunnel.Config().OutAllowZeroHop = b
		return nil
	}
}

//SetCompress tells clients to use compression
func SetCompress(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().UseCompression = b
		c.SAMForwarder.Config().UseCompression = b
		return nil
	}
}

//SetFastRecieve tells clients to use compression
func SetFastRecieve(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().FastRecieve = b
		c.SAMForwarder.Config().FastRecieve = b
		return nil
	}
}

//SetReduceIdle tells the connection to reduce it's tunnels during extended idle time.
func SetReduceIdle(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().ReduceIdle = b
		c.SAMForwarder.Config().ReduceIdle = b
		return nil
	}
}

//SetReduceIdleTime sets the time to wait before reducing tunnels to idle levels
func SetReduceIdleTime(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().ReduceIdleTime = 300000
		c.SAMForwarder.Config().ReduceIdleTime = 300000
		if u >= 6 {
			c.SAMTunnel.Config().ReduceIdleTime = (u * 60) * 1000
			c.SAMForwarder.Config().ReduceIdleTime = (u * 60) * 1000
			return nil
		}
		return fmt.Errorf("Invalid reduce idle timeout(Measured in minutes) %v", u)
	}
}

//SetReduceIdleTimeMs sets the time to wait before reducing tunnels to idle levels in milliseconds
func SetReduceIdleTimeMs(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().ReduceIdleTime = 300000
		c.SAMForwarder.Config().ReduceIdleTime = 300000
		if u >= 300000 {
			c.SAMTunnel.Config().ReduceIdleTime = u
			c.SAMForwarder.Config().ReduceIdleTime = u
			return nil
		}
		return fmt.Errorf("Invalid reduce idle timeout(Measured in milliseconds) %v", u)
	}
}

//SetReduceIdleQuantity sets minimum number of tunnels to reduce to during idle time
func SetReduceIdleQuantity(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if u < 5 {
			c.SAMTunnel.Config().ReduceIdleQuantity = u
			c.SAMForwarder.Config().ReduceIdleQuantity = u
			return nil
		}
		return fmt.Errorf("Invalid reduce tunnel quantity")
	}
}

//SetCloseIdle tells the connection to close it's tunnels during extended idle time.
func SetCloseIdle(b bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().CloseIdle = false
		c.SAMForwarder.Config().CloseIdle = false
		return nil
	}
}

//SetCloseIdleTime sets the time to wait before closing tunnels to idle levels
func SetCloseIdleTime(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().CloseIdleTime = 300000
		c.SAMForwarder.Config().CloseIdleTime = 300000
		if u >= 6 {
			c.SAMTunnel.Config().CloseIdleTime = (u * 60) * 1000
			c.SAMForwarder.Config().CloseIdleTime = (u * 60) * 1000
			return nil
		}
		return fmt.Errorf("Invalid close idle timeout(Measured in minutes) %v", u)
	}
}

//SetCloseIdleTimeMs sets the time to wait before closing tunnels to idle levels in milliseconds
func SetCloseIdleTimeMs(u int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().CloseIdleTime = 300000
		c.SAMForwarder.Config().CloseIdleTime = 300000
		if u >= 300000 {
			c.SAMTunnel.Config().CloseIdleTime = u
			c.SAMForwarder.Config().CloseIdleTime = u
			return nil
		}
		return fmt.Errorf("Invalid close idle timeout(Measured in milliseconds) %v", u)
	}
}

//SetAccessListType tells the system to treat the accessList as a whitelist
func SetAccessListType(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if s == "whitelist" {
			c.SAMTunnel.Config().AccessListType = "whitelist"
			return nil
		} else if s == "blacklist" {
			c.SAMTunnel.Config().AccessListType = "blacklist"
			return nil
		} else if s == "none" {
			c.SAMTunnel.Config().AccessListType = ""
			return nil
		} else if s == "" {
			c.SAMTunnel.Config().AccessListType = ""
			return nil
		}
		return fmt.Errorf("Invalid Access list type(whitelist, blacklist, none)")
	}
}

//SetAccessList tells the system to treat the accessList as a whitelist
func SetAccessList(s []string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		if len(s) > 0 {
			for _, a := range s {
				c.SAMTunnel.Config().AccessList = append(c.SAMTunnel.Config().AccessList, a)
			}
			return nil
		}
		return nil
	}
}

//SetTargetForPort sets the port of the AccessTunnel's SAM bridge using a string
/*func SetTargetForPort443(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		port, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("Invalid Target Port %s; non-number ", s)
		}
		if port < 65536 && port > -1 {
			c.SAMTunnel.Config().TargetForPort443 = s
			return nil
		}
		return fmt.Errorf("Invalid port")
	}
}
*/

//SetKeyFile sets
func SetKeyFile(s string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.SAMTunnel.Config().KeyFilePath = s
		return nil
	}
}

/*
func SetPorts(s []int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
        for _, v := range s {
            c.Rules.Ports = append(c.Rules.Ports, v)
        }
		return nil
	}
}

func SetDomains(s []string) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
        for _, v := range s {
            c.Rules.Domains = append(c.Rules.Domains, v)
        }
		return nil
	}
}

func SetIPs(s []net.IP) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
        for _, v := range s {
            c.Rules.IPs = append(c.Rules.IPs, v)
        }
		return nil
	}
}

func SetLimit(s float64) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.Rules.Limit = s
		return nil
	}
}

func SetBurst(s int) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.Rules.Burst = s
		return nil
	}
}

func SetPolicy(s bool) func(*AccessTunnel) error {
	return func(c *AccessTunnel) error {
		c.Rules.Default = s
		return nil
	}
}
*/
