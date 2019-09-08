package whitelister

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	//"golang.org/x/crypto/bcrypt"

	"github.com/eyedeekay/sam-forwarder/hashhash"
)

// RandString generates a random, 6-character string
func RandString() string {
	b := make([]byte, 6)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz"[rand.Intn(len("abcdefghijklmnopqrstuvwxyz"))]
	}
	return string(b)
}

// OneTimePassword is an account-generation method where a password is
// pre-generated. The administrator of the VPN gives that password to a client,
// and the client uses it to create an account. After this, that password cannot
// be re-used to create a new account.
type OneTimePassword struct {
	CurrentPass string
	Revokables  map[string]string
	cache       map[string]time.Time
	hasher      *hashhash.Hasher
}

func (o *OneTimePassword) addCache(user string) {
	t := time.Now()
	o.cache[user] = t.Add((time.Minute * 5))
}

func (o *OneTimePassword) checkCache(user string) bool {
	if v, ok := o.cache[user]; !ok {
		return false
	} else {
		return v.After(time.Now())
	}
}

// RefreshPassword generates a new password to replace the old password with.
func (o *OneTimePassword) RefreshPassword() string {
	fr, _ := o.hasher.Friendly(RandString())
	return fr
}

// CurrentPassword returns the current password for creating a new account.
func (o *OneTimePassword) CurrentPassword() string {
	return o.CurrentPass
}

// Check determines if the string or bytes it is passed correspond to a current
// password. If so, it creates an account. If the password corresponds to an
// already created account, then the the user is informed the account is active
// and if not, it says the user is anauthorized.
func (o *OneTimePassword) Check(bodyStringOrBytes interface{}) (string, interface{}, bool) {
	var r string
	switch bodyStringOrBytes.(type) {
	case string:
		r = bodyStringOrBytes.(string)
	case []byte:
		r = string(bodyStringOrBytes.([]byte))
	default:
		return "", nil, false
	}
	var creds Credentials
	err := json.NewDecoder(strings.NewReader(r)).Decode(&creds)
	if err != nil {
		return creds.Base64, nil, false
	}
	if creds.Password == o.CurrentPass {
		o.Revokables[creds.Base64] = o.CurrentPass + ":" + time.Now().String()
		o.CurrentPass = o.RefreshPassword()
		return creds.Base64, nil, true
	}
	if v, ok := o.Revokables[creds.Base64]; ok {
		pass := strings.Split(v, ":")[0]
		if pass == creds.Password {
			return creds.Base64, nil, true
		}
	}
	return creds.Base64, nil, false
}

func (o *OneTimePassword) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	body, err := ioutil.ReadAll(rq.Body)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	base64, _, valid := o.Check(body)
	if valid {
		if o.checkCache(base64) {
			rw.WriteHeader(http.StatusAccepted)
			io.WriteString(rw, "Congratulations, "+base64+" your account is online \n")
			return
		} else {
			rw.WriteHeader(http.StatusAccepted)
			o.addCache(base64)
		}
	} else {
		rw.WriteHeader(http.StatusUnauthorized)
	}
}

// Whitelist prints the whitelist of keys to be consumed by a tunnel
func (o *OneTimePassword) Whitelist() []string {
	var r []string
	for k := range o.Revokables {
		s := strings.Split(k, ":")[0]
		r = append(r, s)
	}
	return r
}

// NewOneTimePassRotator generates a new whitelister using the One-Time-Password
// creation pattern
func NewOneTimePassRotator() (*OneTimePassword, error) {
	hasher, err := hashhash.NewHasher(6)
	if err != nil {
		return nil, err
	}
	pass, err := hasher.Friendly(RandString())
	if err != nil {
		return nil, err
	}
	o := OneTimePassword{
		CurrentPass: pass,
		hasher:      hasher,
	}
	return &o, nil
}

var otp WhiteLister = &OneTimePassword{}
