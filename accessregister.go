package outproxy

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/eyedeekay/accessregister/auth"
	"github.com/eyedeekay/eephttpd"
	"github.com/eyedeekay/httptunnel"
	"github.com/eyedeekay/httptunnel/multiproxy"
	"github.com/eyedeekay/sam-forwarder/config"
	"github.com/eyedeekay/sam-forwarder/interface"
	"github.com/eyedeekay/sam-forwarder/tcp"
	"github.com/eyedeekay/sam-forwarder/udp"
	"github.com/eyedeekay/sam3/i2pkeys"
	"github.com/phayes/freeport"
)

// AccessTunnel is a SAM-based SOCKS outproxy you connect to with a regular TCP
// tunnel
type AccessTunnel struct {
	samtunnel.SAMTunnel
	*samforwarder.SAMForwarder
	Whitelister []whitelister.WhiteLister
	up          bool
}

var err error

func (f *AccessTunnel) Check(requestBytesOrString interface{}) (string, interface{}, bool) {
	for _, v := range f.Whitelister {
		if base64, extra, ok := v.Check(requestBytesOrString); ok {
			return base64, extra, ok
		}
	}
	return "", nil, false
}

func (f *AccessTunnel) Whitelist() []string {
	var r []string
	for _, w := range f.Whitelister {
		for _, v := range w.Whitelist() {
			r = append(r, v)
		}
	}
	return r
}

func (f *AccessTunnel) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	for _, w := range f.Whitelister {
		if rq.URL.Path == w.String() {
			w.ServeHTTP(rw, rq)
			return
		}
	}
	io.WriteString(rw, "Please choose a valid form of registration for your")
	io.WriteString(rw, "account.")
	for _, w := range f.Whitelister {
		io.WriteString(rw, "<a href=/\""+w.String()+"\">"+w.String()+"</a><br>")
	}
}

func (f *AccessTunnel) Config() *i2ptunconf.Conf {
	return f.SAMTunnel.Config()
}

func (f *AccessTunnel) ID() string {
	return f.Config().ID()
}

func (f *AccessTunnel) Keys() i2pkeys.I2PKeys {
	return f.SAMTunnel.Keys()
}

func (f *AccessTunnel) Cleanup() {
	f.SAMTunnel.Cleanup()
}

func (f *AccessTunnel) GetType() string {
	return f.SAMTunnel.GetType()
}

/*func (f *AccessTunnel) targetForPort443() string {
	if f.TargetForPort443 != "" {
		return "targetForPort.4443=" + f.TargetHost + ":" + f.TargetForPort443
	}
	return ""
}*/

func (f *AccessTunnel) Props() map[string]string {
	var r map[string]string
	for k, v := range f.SAMTunnel.Props() {
		r[k] = v
	}
	for k, v := range f.SAMForwarder.Props() {
		r["registrar."+k] = v
	}
	return r
}

func (f *AccessTunnel) Print() string {
	return f.SAMTunnel.Print()
}

func (f *AccessTunnel) Search(search string) string {
	return f.SAMTunnel.Search(search)
}

// Target returns the host:port of the local service you want to forward to i2p
func (f *AccessTunnel) Target() string {
	return f.SAMTunnel.Target()
}

//Base32 returns the base32 address where the local service is being forwarded
func (f *AccessTunnel) Base32() string {
	return f.SAMTunnel.Base32()
}

//Base32Readable returns the base32 address where the local service is being forwarded
func (f *AccessTunnel) Base32Readable() string {
	return f.SAMTunnel.Base32Readable()
}

//Base64 returns the base64 address where the local service is being forwarded
func (f *AccessTunnel) Base64() string {
	return f.SAMTunnel.Base64()
}

func (f *AccessTunnel) ServeParent() {
	log.Println("Starting eepsite server", f.Base32())
	if err = f.SAMTunnel.Serve(); err != nil {
		f.Cleanup()
	}
}

func (f *AccessTunnel) ServeRegistrar() {
	log.Println("Starting eepsite server", f.Base32())
	if err = f.SAMForwarder.Serve(); err != nil {
		f.Cleanup()
	}
}

//Serve starts the SAM connection and and forwards the local host:port to i2p
func (f *AccessTunnel) Serve() error {
	go f.ServeParent()
	go f.ServeRegistrar()
	if f.Up() {
		log.Println("Starting registrar", f.SAMForwarder.Target())
		if err := http.ListenAndServe(f.SAMForwarder.Target(), f); err != nil {
			panic(err)
		}
	}
	return nil
}

func (f *AccessTunnel) Up() bool {
	if f.SAMTunnel.Up() {
		return true
	}
	return false
}

//Close shuts the whole thing down.
func (f *AccessTunnel) Close() error {
	return f.SAMTunnel.Close()
}

func (s *AccessTunnel) Load() (samtunnel.SAMTunnel, error) {
	if !s.up {
		log.Println("Started putting tunnel up")
	}
	f, e := s.SAMTunnel.Load()
	if e != nil {
		return nil, e
	}
	switch s.SAMTunnel.GetType() {
	case "server":
		s.SAMTunnel = f.(*samforwarder.SAMForwarder)
	case "http":
		s.SAMTunnel = f.(*samforwarder.SAMForwarder)
	case "client":
		s.SAMTunnel = f.(*samforwarder.SAMClientForwarder)
	case "httpclient":
		s.SAMTunnel = f.(*i2phttpproxy.SAMHTTPProxy)
	case "browserclient":
		s.SAMTunnel = f.(*i2pbrowserproxy.SAMMultiProxy)
	case "udpserver":
		s.SAMTunnel = f.(*samforwarderudp.SAMSSUForwarder)
	case "udpclient":
		s.SAMTunnel = f.(*samforwarderudp.SAMSSUClientForwarder)
	case "eephttpd":
		s.SAMTunnel = f.(*eephttpd.EepHttpd)
	case "vpnserver":
		return nil, fmt.Errorf("Error: %s isn't implemented yet", "eephttpd")
	case "vpnclient":
		return nil, fmt.Errorf("Error: %s isn't implemented yet", "eephttpd")
	case "kcpclient":
		return nil, fmt.Errorf("Error: %s isn't implemented", "eephttpd")
	case "kcpserver":
		return nil, fmt.Errorf("Error: %s isn't implemented", "eephttpd")
	default:
		s.SAMTunnel = f.(*samforwarder.SAMForwarder)
	}

	w, err := s.SAMForwarder.Load()
	if err != nil {
		return nil, err
	}
	s.SAMForwarder = w.(*samforwarder.SAMForwarder)
	s.up = true
	log.Println("Finished putting tunnel up")
	return s, nil
}

//NewAccessTunneld makes a new SAM forwarder with default options, accepts host:port arguments
func NewAccessTunnel(host, port string) (*AccessTunnel, error) {
	return NewAccessTunnelFromOptions(SetHost(host), SetPort(port))
}

//NewAccessTunneldFromOptions makes a new SAM forwarder with default options, accepts host:port arguments
func NewAccessTunnelFromOptions(opts ...func(*AccessTunnel) error) (*AccessTunnel, error) {
	var s AccessTunnel
	//s.SAMTunnel
	s.SAMForwarder = &samforwarder.SAMForwarder{}
	log.Println("Initializing outproxy")
	for _, o := range opts {
		if err := o(&s); err != nil {
			return nil, err
		}
	}
	s.SAMTunnel.Config().SaveFile = true
	log.Println("Options loaded", s.Print())
	if len(s.Whitelister) == 0 {
		w, err := whitelister.NewOneTimePassRotator()
		if err != nil {
			return nil, err
		}
		s.Whitelister = append(s.Whitelister, w)

	}
	port, e := freeport.GetFreePort()
	if e != nil {
		return nil, e
	}
	s.SAMForwarder.Config().TargetPort = strconv.Itoa(port)
	l, e := s.Load()
	if e != nil {
		return nil, e
	}
	return l.(*AccessTunnel), nil
}
