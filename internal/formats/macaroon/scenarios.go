package macaroon

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	fly "github.com/superfly/macaroon"
	"github.com/superfly/macaroon/auth"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"

	"github.com/kanywst/whosent/internal/safewrite"
	"github.com/kanywst/whosent/pkg/chain"
)

// The demos mint their macaroons on every run with fixed keys and nonces,
// so they are the same bytes each time and never expire in a committed
// file.

var (
	demoRootKey  = []byte("whosent demo root key")
	demoThirdKey = []byte("whosent demo third-party key")
	flySignKey   = bytes.Repeat([]byte{0xf1}, 32)
	flyAuthKey   = bytes.Repeat([]byte{0xa1}, 32)
)

const (
	bankLocation = "https://bank.example"
	authLocation = "https://auth.example"
)

func until(t time.Time) string { return "time < " + t.UTC().Format(time.RFC3339) }

// demo is one minted scenario: the token text and what it is checked
// against.
type demo struct {
	data  []byte
	key   []byte
	facts []string
}

type spec struct {
	name, title, summary string
	build                func(base time.Time) demo
}

var bankFacts = []string{"account = 3735928559", "action = deposit"}

// bank mints the healthy root: an account, an action, an hour, and a
// third-party caveat the auth service answers with a twenty-minute
// discharge.
func bank(base time.Time, withDischarge bool, rootTime time.Time) []*lmac {
	root := mintLib(demoRootKey, "account-key-7", bankLocation)
	root.first("account = 3735928559").first("action = deposit").first(until(rootTime))
	k := root.third(demoThirdKey, "user = alice", authLocation, 0x24)
	out := []*lmac{root.m}
	if withDischarge {
		d := mintDischarge(k, "user = alice", authLocation).first(until(base.Add(20 * time.Minute)))
		d.bind(root.m)
		out = append(out, d.m)
	}
	return out
}

func libDemo(ms []*lmac, key []byte, facts []string) demo {
	var raw []byte
	for _, m := range ms {
		b, err := m.encodeV2()
		if err != nil {
			panic(err)
		}
		raw = append(raw, b...)
	}
	return demo{data: []byte(base64.RawURLEncoding.EncodeToString(raw) + "\n"), key: key, facts: facts}
}

var specs = []spec{
	{"macaroon-healthy", "A bank macaroon and its discharge",
		"a bank's macaroon, narrowed to one account, deposits and an hour, with a third-party caveat the auth service discharged for twenty minutes. The root key and the predicates are given.",
		func(base time.Time) demo {
			return libDemo(bank(base, true, base.Add(time.Hour)), demoRootKey, bankFacts)
		}},
	{"macaroon-missing-discharge", "A caveat nobody discharged",
		"the same macaroon sent without the auth service's discharge: the third-party caveat stands unanswered, and a verifier refuses it.",
		func(base time.Time) demo {
			return libDemo(bank(base, false, base.Add(time.Hour)), demoRootKey, bankFacts)
		}},
	{"macaroon-tampered", "A caveat rewritten",
		"the holder rewrote `action = deposit` to `action = withdraw`. The caveat reads well, but the HMAC chain no longer matches under the root key.",
		func(base time.Time) demo {
			ms := bank(base, true, base.Add(time.Hour))
			ms[0].caveats[1].id = []byte("action = withdraw")
			return libDemo(ms, demoRootKey, []string{"account = 3735928559", "action = withdraw"})
		}},
	{"macaroon-expired", "An hour that ran out",
		"the bank's time caveat ended before now; the chain is intact, but a verifier refuses it from that caveat on.",
		func(base time.Time) demo {
			return libDemo(bank(base, true, base.Add(-5*time.Minute)), demoRootKey, bankFacts)
		}},
	{"macaroon-unchecked", "No root key, no predicates",
		"the healthy macaroon opened with nothing to check it against: every caveat reads, none can be vouched for.",
		func(base time.Time) demo {
			return libDemo(bank(base, true, base.Add(time.Hour)), nil, nil)
		}},
	{"macaroon-fly", "A Fly.io token",
		"a Fly.io-style token for one organization and one app, read-write, discharged by the auth service with a proof bound to the token. The token holds; ask tests a request against its caveats.",
		func(base time.Time) demo {
			return demo{data: []byte(flyDemo(base) + "\n"), key: flySignKey}
		}},
}

func flyDemo(base time.Time) string {
	root := mintFly(flySignKey, []byte("org-token-1"), "https://api.fly.example/v1", 0x11, false)
	root.add(&flyio.Organization{ID: 4242, Mask: resset.ActionRead | resset.ActionWrite})
	root.add(&flyio.Apps{Apps: resset.ResourceSet[uint64, resset.Action]{123: resset.ActionRead | resset.ActionWrite}})
	root.add(&fly.ValidityWindow{NotBefore: base.Add(-time.Hour).Unix(), NotAfter: base.Add(24 * time.Hour).Unix()})
	ticket, dk := root.third(flyAuthKey, "https://auth.fly.example", 0x31)
	d := mintFly(dk, ticket, "https://auth.fly.example", 0x41, true)
	d.add(&fly.ValidityWindow{NotBefore: base.Add(-time.Minute).Unix(), NotAfter: base.Add(30 * time.Minute).Unix()})
	uid := auth.FlyioUserID(1001)
	d.add(&uid)
	d.bind(root.m)
	return flyHeader(root.encode(), d.encode())
}

func (d demo) session(name string, base time.Time) (*session, error) {
	b, err := decode(d.data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	s := &session{b: b, key: d.key, skew: DefaultSkew, source: name, at: base.Add(time.Minute)}
	if d.key != nil {
		s.demo = "demo root key"
	}
	if b.dialect != "fly" {
		s.facts = map[string]bool{}
		for _, f := range d.facts {
			s.facts[f] = true
		}
		s.factsGiven = len(d.facts) > 0
	}
	return s, nil
}

func scenarios() []chain.Scenario {
	var out []chain.Scenario
	for _, sp := range specs {
		sp := sp
		out = append(out, chain.Scenario{
			Name: sp.name, Title: sp.title, Summary: sp.summary, Format: ID,
			Open: func(base time.Time) (chain.Session, error) {
				return sp.build(base).session(sp.name, base)
			},
			Emit: func(dir string, force bool) (string, error) { return emit(sp, dir, force) },
		})
	}
	return out
}

// emitBase is the time emitted fixtures are minted at, so they are the
// same bytes on every run.
var emitBase = time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)

func emit(sp spec, dir string, force bool) (string, error) {
	d := sp.build(emitBase)
	if err := safewrite.Dir(dir, force); err != nil {
		return "", err
	}
	files := map[string][]byte{"token.txt": d.data}
	args := []string{"whosent check token.txt --format macaroon"}
	if d.key != nil {
		files["root.key"] = []byte(hex.EncodeToString(d.key) + "\n")
		args = append(args, "--root-key root.key")
	}
	for _, f := range d.facts {
		args = append(args, "--fact '"+f+"'")
	}
	args = append(args, "--at "+emitBase.Add(time.Minute).Format(time.RFC3339))
	command := strings.Join(args, " ")
	manifest, err := json.MarshalIndent(map[string]string{
		"name": sp.name, "title": sp.title, "summary": sp.summary, "format": ID, "command": command,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	files["manifest.json"] = append(manifest, '\n')
	for name, data := range files {
		if err := safewrite.File(filepath.Join(dir, name), data); err != nil {
			return "", err
		}
	}
	return command, nil
}
