package accessregister

import (
	"log"
	"testing"

	"github.com/eyedeekay/accessregister/auth"
	"github.com/eyedeekay/sam-forwarder/interface"
)

func TestImpl(t *testing.T) {
	var w whitelister.WhiteLister
	w = &AccessTunnel{}
	log.Println(w)
	var x samtunnel.SAMTunnel
	x = &AccessTunnel{}
	log.Println(x)
}
