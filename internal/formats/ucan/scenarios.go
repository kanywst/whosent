package ucan

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/safewrite"
	"github.com/kanywst/whosent/pkg/chain"
)

// The demos mint their tokens on every run from fixed seeds, so they are
// the same bytes each time and never expire in a committed file.

var (
	alice     = newSigner("alice", 0xa1)
	assistant = newSigner("assistant", 0xa2)
	mailer    = newSigner("mailer", 0xa3)
	mallory   = newSigner("mallory", 0xa4)
	mailbox   = newSigner("mailbox", 0xa5)
	tablet    = newSigner("tablet", 0xa6)
)

var cast = []signer{alice, assistant, mailer, mallory, mailbox, tablet}

func names() map[string]string {
	m := map[string]string{}
	for _, s := range cast {
		m[s.DID] = s.Name
	}
	return m
}

// seal signs a payload into an envelope.
func seal(s signer, tag string, payload Value) []byte {
	sp := vMap(entry("h", vBytes(edHeader.encode())), entry(tag, payload))
	return encodeCBOR(vList(vBytes(s.sign(encodeCBOR(sp))), sp))
}

// dlgSpec is one delegation to mint.
type dlgSpec struct {
	iss  signer
	aud  string
	sub  *string // nil: powerline
	cmd  string
	pol  []Value
	nbf  *int64
	exp  int64
	seal signer // who signs; iss unless a forgery
}

func (d dlgSpec) mint(nonce byte) []byte {
	pol := vList(d.pol...)
	sub := vNull()
	if d.sub != nil {
		sub = vStr(*d.sub)
	}
	es := []Entry{
		entry("iss", vStr(d.iss.DID)), entry("aud", vStr(d.aud)), entry("sub", sub),
		entry("cmd", vStr(d.cmd)), entry("pol", pol), entry("exp", vInt(d.exp)),
		entry("nonce", vBytes([]byte{nonce, nonce, nonce, nonce, nonce, nonce, nonce, nonce})),
	}
	if d.nbf != nil {
		es = append(es, entry("nbf", vInt(*d.nbf)))
	}
	by := d.seal
	if by.DID == "" {
		by = d.iss
	}
	return seal(by, tagDelegation, vMap(es...))
}

// invSpec is the invocation to mint.
type invSpec struct {
	iss  signer
	sub  string
	cmd  string
	args Value
	exp  int64
	iat  int64
}

func (v invSpec) mint(prf [][]byte) []byte {
	links := make([]Value, len(prf))
	for i, p := range prf {
		links[i] = vLink(cidOf(p))
	}
	return seal(v.iss, tagInvocation, vMap(
		entry("iss", vStr(v.iss.DID)), entry("sub", vStr(v.sub)), entry("cmd", vStr(v.cmd)),
		entry("args", v.args), entry("prf", vList(links...)), entry("exp", vInt(v.exp)),
		entry("iat", vInt(v.iat)), entry("nonce", vBytes([]byte{0x0f, 0x0f, 0x0f, 0x0f})),
	))
}

func str(s string) *string { return &s }

func stmt(vs ...Value) Value { return vList(vs...) }

// The mail policy from the delegation spec's own example: alice's address
// on every message, and at least one recipient at example.com.
var mailPolicy = []Value{
	stmt(vStr("=="), vStr(".from"), vStr("alice@example.com")),
	stmt(vStr("any"), vStr(".to"), stmt(vStr("like"), vStr("."), vStr("*@example.com"))),
}

func coffee() Value {
	return vMap(
		entry("from", vStr("alice@example.com")),
		entry("to", vList(vStr("bob@example.com"))),
		entry("subject", vStr("Coffee?")),
	)
}

// demo is one minted scenario.
type demo struct {
	tokens  [][]byte
	revoked [][]byte
	// noRevoke leaves the revocation list out.
	noRevoke bool
}

type spec struct {
	name, title, summary string
	build                func(base time.Time) demo
}

// healthy is alice's chain: she lets her assistant send mail, the
// assistant hands sending to a mailer under the spec's mail policy, and
// the mailer sends a message.
func healthy(base time.Time, change func(ds []dlgSpec, inv *invSpec)) demo {
	at := base.Unix()
	ds := []dlgSpec{
		{iss: alice, aud: assistant.DID, sub: str(alice.DID), cmd: "/msg", exp: at + 3600},
		{iss: assistant, aud: mailer.DID, sub: str(alice.DID), cmd: "/msg/send", pol: mailPolicy, exp: at + 2400},
	}
	inv := invSpec{iss: mailer, sub: alice.DID, cmd: "/msg/send", args: coffee(), exp: at + 300, iat: at}
	if change != nil {
		change(ds, &inv)
	}
	var toks [][]byte
	for i, d := range ds {
		toks = append(toks, d.mint(byte(0x10+i)))
	}
	return demo{tokens: append(toks, inv.mint(toks))}
}

var specs = []spec{
	{"ucan-healthy", "Mail, sent on alice's behalf",
		"alice lets her assistant send mail; the assistant hands sending to a mailer, only as alice and only to example.com. The mailer sends one message: every rule holds.",
		func(base time.Time) demo { return healthy(base, nil) }},
	{"ucan-widened", "A command wider than its grant",
		"the assistant was given /msg/send, and passed on all of /msg. Every signature holds; the command does not.",
		func(base time.Time) demo {
			return healthy(base, func(ds []dlgSpec, _ *invSpec) {
				ds[0].cmd, ds[1].cmd = "/msg/send", "/msg"
			})
		}},
	{"ucan-misaligned", "A delegation from the wrong hand",
		"mallory signs the second delegation herself, though alice addressed the first to her assistant. mallory's signature is real; she was never given anything.",
		func(base time.Time) demo {
			return healthy(base, func(ds []dlgSpec, _ *invSpec) { ds[1].iss = mallory })
		}},
	{"ucan-expired", "A delegation past its time",
		"the assistant's delegation to the mailer ran out five minutes before the message was sent.",
		func(base time.Time) demo {
			return healthy(base, func(ds []dlgSpec, _ *invSpec) { ds[1].exp = base.Unix() - 300 })
		}},
	{"ucan-forged", "A signature by someone else",
		"the second delegation names the assistant as its issuer, but mallory signed it.",
		func(base time.Time) demo {
			return healthy(base, func(ds []dlgSpec, _ *invSpec) { ds[1].seal = mallory })
		}},
	{"ucan-policy", "Arguments the policy refuses",
		"the mailer writes to someone outside example.com. Every token holds; the assistant's policy does not.",
		func(base time.Time) demo {
			return healthy(base, func(_ []dlgSpec, inv *invSpec) {
				inv.args = vMap(entry("from", vStr("alice@example.com")), entry("to", vList(vStr("eve@elsewhere.example"))), entry("subject", vStr("Coffee?")))
			})
		}},
	{"ucan-powerline", "One subject's mail, any device",
		"alice's mailbox lets alice send. alice passes all she holds to her tablet with a powerline (sub: null), and the tablet sends as her.",
		func(base time.Time) demo {
			at := base.Unix()
			d0 := dlgSpec{iss: mailbox, aud: alice.DID, sub: str(mailbox.DID), cmd: "/msg/send", exp: at + 3600}.mint(0x20)
			d1 := dlgSpec{iss: alice, aud: tablet.DID, cmd: "/msg/send", exp: at + 2400}.mint(0x21)
			inv := invSpec{iss: tablet, sub: mailbox.DID, cmd: "/msg/send", args: coffee(), exp: at + 300, iat: at}.mint([][]byte{d0, d1})
			return demo{tokens: [][]byte{d0, d1, inv}}
		}},
	{"ucan-revoked", "A revoked delegation",
		"alice revoked her delegation to the assistant. Everything below it goes with it.",
		func(base time.Time) demo {
			d := healthy(base, nil)
			d.revoked = [][]byte{d.tokens[0]}
			return d
		}},
	{"ucan-unchecked", "No revocation list",
		"the healthy chain, checked without a revocation list: UCAN revocation lives with the executor, so nothing here vouches for it.",
		func(base time.Time) demo {
			d := healthy(base, nil)
			d.noRevoke = true
			return d
		}},
}

func (d demo) options() Options {
	// The command line's default skew, so a demo reads as its emitted
	// fixture checks.
	o := Options{Names: names(), Skew: 30 * time.Second}
	if !d.noRevoke {
		o.Revoked = map[string]bool{}
		for _, r := range d.revoked {
			o.Revoked[cidText(cidOf(r))] = true
		}
		o.RevokedSource = "demo revocation list"
	}
	return o
}

// Scenarios are UCAN's demos.
func (Adapter) Scenarios() []chain.Scenario {
	var out []chain.Scenario
	for _, sp := range specs {
		sp := sp
		out = append(out, chain.Scenario{
			Name: sp.name, Title: sp.title, Summary: sp.summary, Format: ID,
			Open: func(base time.Time) (chain.Session, error) {
				d := sp.build(base)
				var toks []*Token
				for _, t := range d.tokens {
					toks = append(toks, decodeToken(t))
				}
				return &Session{tokens: toks, inputFormat: "demo", opts: d.options(), at: base.Add(time.Minute), source: sp.name}, nil
			},
			Emit: func(dir string, force bool) (string, error) {
				return emit(sp, dir, force)
			},
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
	var arr []string
	for _, t := range d.tokens {
		arr = append(arr, base64.StdEncoding.EncodeToString(t))
	}
	tokens, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return "", err
	}
	files := map[string][]byte{"tokens.json": append(tokens, '\n')}
	args := []string{"whosent check tokens.json --format ucan"}
	if !d.noRevoke {
		var ids strings.Builder
		ids.WriteString("# revoked UCAN delegation CIDs, one per line\n")
		for _, r := range d.revoked {
			ids.WriteString(cidText(cidOf(r)) + "\n")
		}
		files["revoked-cids.txt"] = []byte(ids.String())
		args = append(args, "--revoked-jtis revoked-cids.txt")
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
