package whitelister

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserNamePassword struct {
	admin string
	pass  string
	Pairs map[string][]string
	cache map[string]time.Time
}

func (o *UserNamePassword) addCache(user string) {
	t := time.Now()
	o.cache[user] = t.Add((time.Minute * 5))
}

func (o *UserNamePassword) checkCache(user string) bool {
	if v, ok := o.cache[user]; !ok {
		return false
	} else {
		return v.After(time.Now())
	}
}

func (o *UserNamePassword) Check(bodyStringOrBytes interface{}) (string, interface{}, bool) {
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
	userbu, err := bcrypt.GenerateFromPassword([]byte(creds.Username), 14)
	if err != nil {
		return "", nil, false
	}
	if v, ok := o.Pairs[string(userbu)]; ok {
		userbp, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 14)
		if err != nil {
			return "", nil, false
		}
		if v[0] == string(userbp) {
			for _, w := range v[1:] {
				if w == creds.Base64 {
					return creds.Base64, nil, true
				}
			}
			o.Pairs[creds.Username] = append(o.Pairs[creds.Username], creds.Base64)
			return creds.Base64, nil, true
		}
	}
	return creds.Base64, nil, false
}

func (o *UserNamePassword) CheckAdmin(bodyStringOrBytes interface{}) (string, bool) {
	var r string
	switch bodyStringOrBytes.(type) {
	case string:
		r = bodyStringOrBytes.(string)
	case []byte:
		r = string(bodyStringOrBytes.([]byte))
	default:
		return "", false
	}
	var creds AdminCredentials
	err := json.NewDecoder(strings.NewReader(r)).Decode(&creds)
	if err != nil {
		return "", false
	}
	admbu, err := bcrypt.GenerateFromPassword([]byte(creds.Username), 14)
	if err != nil {
		return "", false
	}
	admbp, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 14)
	if err != nil {
		return "", false
	}
	if string(admbu) == o.admin {
		if string(admbp) == o.pass {
			if _, ok := o.Pairs[creds.NewUser]; !ok {
				userbu, err := bcrypt.GenerateFromPassword([]byte(creds.NewUser), 14)
				if err != nil {
					return "", true
				}
				userbp, err := bcrypt.GenerateFromPassword([]byte(creds.NewPass), 14)
				if err != nil {
					return "", true
				}
				o.Pairs[string(userbu)] = []string{string(userbp)}
				return "Created new user: " + creds.NewUser, true
			}
			return "", true
		}
	}
	return "", false
}

func (o *UserNamePassword) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	body, err := ioutil.ReadAll(rq.Body)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	if msg, done := o.CheckAdmin(body); done {
		io.WriteString(rw, msg)
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

func (o *UserNamePassword) Whitelist() []string {
	var r []string
	for _, v := range o.Pairs {
		if len(v) > 1 {
			for _, w := range v[1:] {
				r = append(r, w)
			}
		}
	}
	return r
}

func (o *UserNamePassword) String() string {
	return "unp"
}

// pairs map[string][]string
func NewUserNamePassword(adminuser, adminpass string) (*UserNamePassword, error) {
	admbu, err := bcrypt.GenerateFromPassword([]byte(adminuser), 14)
	if err != nil {
		return nil, err
	}
	admbp, err := bcrypt.GenerateFromPassword([]byte(adminpass), 14)
	if err != nil {
		return nil, err
	}
	o := UserNamePassword{
		admin: string(admbu),
		pass:  string(admbp),
	}
	return &o, nil
}

var unp WhiteLister = &UserNamePassword{}
