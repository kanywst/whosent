package biscuit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/internal/safewrite"
	"github.com/kanywst/whosent/pkg/chain"
)

// The demos mint their tokens on every run from fixed seeds, so they are
// the same bytes each time and never expire in a committed file.

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

var (
	rootSigner  = SignerFromSeed(seed(0xb0))
	thirdSigner = SignerFromSeed(seed(0xc0))
)

func blockSigner(i int) Signer { return SignerFromSeed(seed(0xb1 + byte(i))) }

func p256Signer(i int) Signer {
	s, err := P256SignerFromSeed(seed(0xd0 + byte(i)))
	if err != nil {
		panic(err)
	}
	return s
}

func date(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// demo is one minted scenario: a token and what it is checked against.
type demo struct {
	tok       *Token
	root      Signer
	facts     []string
	policy    string
	revoked   []string
	noRootKey bool
	noRevoke  bool
	noAuth    bool
}

type spec struct {
	name, title, summary string
	build                func(base time.Time) (demo, error)
}

// The healthy token every scenario starts from: a billing service's grant,
// narrowed by the payments team to reading, then by a reporting bot to two
// resources and a shorter life.
func healthyBlocks(base time.Time) []BlockSpec {
	return []BlockSpec{
		{Context: "billing service", Source: fmt.Sprintf(`
			right("orders", "read");
			right("orders", "write");
			right("invoices", "read");
			right("refunds", "write");
			check if resource($r), operation($op), right($r, $op);
			check if time($t), $t <= %s;`, date(base.Add(time.Hour)))},
		{Context: "payments team", Source: fmt.Sprintf(`
			check if operation("read");
			check if time($t), $t <= %s;`, date(base.Add(40*time.Minute)))},
		{Context: "reporting bot", Source: fmt.Sprintf(`
			check if resource($r), {"orders", "invoices"}.contains($r);
			check if time($t), $t <= %s;`, date(base.Add(20*time.Minute)))},
	}
}

func mintAll(root Signer, signers func(int) Signer, blocks []BlockSpec) (*Minter, error) {
	m, err := Mint(root, signers(0), blocks[0])
	if err != nil {
		return nil, err
	}
	for i, b := range blocks[1:] {
		if err := m.Append(signers(i+1), b); err != nil {
			return nil, err
		}
	}
	return m, nil
}

var readOrders = []string{`resource("orders")`, `operation("read")`}

var specs = []spec{
	{"biscuit-healthy", "A grant narrowed twice",
		"a billing service's grant, narrowed to reading by the payments team, then to two resources and twenty minutes by a reporting bot. The bot reads orders: every check holds.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			return demo{tok: tok, root: rootSigner, facts: readOrders}, err
		}},
	{"biscuit-denied", "A write the token cannot make",
		"the same token, asked to write orders. The payments team's block allows reading only, so its check fails, and the request stops there.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			return demo{tok: tok, root: rootSigner, facts: []string{`resource("orders")`, `operation("write")`}}, err
		}},
	{"biscuit-expired", "A block past its time",
		"the reporting bot's block expired five minutes before it was used. Every signature holds; its time check does not.",
		func(base time.Time) (demo, error) {
			blocks := healthyBlocks(base)
			blocks[2].Source = fmt.Sprintf(`
			check if resource($r), {"orders", "invoices"}.contains($r);
			check if time($t), $t <= %s;`, date(base.Add(-5*time.Minute)))
			m, err := mintAll(rootSigner, blockSigner, blocks)
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			return demo{tok: tok, root: rootSigner, facts: readOrders}, err
		}},
	{"biscuit-forged", "A block edited after signing",
		"someone deleted the reporting bot's resource check after the block was signed. The block's signature no longer verifies, so nothing it claims counts.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			if err != nil {
				return demo{}, err
			}
			edited, _, err := encodeBlockAt(BlockSpec{Context: "reporting bot", Source: fmt.Sprintf(`
			check if time($t), $t <= %s;`, date(base.Add(20*time.Minute)))}, tok, 2)
			if err != nil {
				return demo{}, err
			}
			tok.Blocks[2].Data = edited
			return demo{tok: tok, root: rootSigner, facts: readOrders}, nil
		}},
	{"biscuit-reordered", "Blocks out of order",
		"the payments team's and the reporting bot's blocks were swapped. Each block is signed by the key the one before it handed on, so neither verifies where it now sits.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			if err != nil {
				return demo{}, err
			}
			tok.Blocks[1], tok.Blocks[2] = tok.Blocks[2], tok.Blocks[1]
			return demo{tok: tok, root: rootSigner, facts: readOrders}, nil
		}},
	{"biscuit-revoked", "A revoked block",
		"the payments team's block is on the revocation list. A Biscuit is refused if any of its blocks is revoked, so the bot's block below it holds nothing.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			if err != nil {
				return demo{}, err
			}
			return demo{tok: tok, root: rootSigner, facts: readOrders, revoked: []string{hexID(tok.Blocks[1].Signature)}}, nil
		}},
	{"biscuit-third-party", "A third party vouches",
		"the admin console grants reading only to members of the support group, and trusts an identity provider's key to say who is. The provider signs a block saying this holder is.",
		func(base time.Time) (demo, error) {
			idp := thirdSigner.Pub.String()
			m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Context: "admin console", Source: fmt.Sprintf(`
				right("tickets", "read");
				check if resource($r), operation($op), right($r, $op);
				check if group("support") trusting %s;
				check if time($t), $t <= %s;`, idp, date(base.Add(time.Hour)))})
			if err != nil {
				return demo{}, err
			}
			if err := m.AppendThirdParty(blockSigner(1), thirdSigner, BlockSpec{Context: "identity provider", Source: fmt.Sprintf(`
				group("support");
				check if time($t), $t <= %s;`, date(base.Add(30*time.Minute)))}); err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			return demo{tok: tok, root: rootSigner, facts: []string{`resource("tickets")`, `operation("read")`}}, err
		}},
	{"biscuit-sealed", "A sealed token",
		"the reporting bot sealed its token: the proof is a signature instead of the last private key, so nobody can append a block, not even the bot.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Sealed()
			return demo{tok: tok, root: rootSigner, facts: readOrders}, err
		}},
	{"biscuit-p256", "ECDSA P-256 keys",
		"the same grant, with every key on the P-256 curve: the signatures use the version 1 payload, which commits each block to the one before it.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(p256Signer(0), func(i int) Signer { return p256Signer(i + 1) }, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			return demo{tok: tok, root: p256Signer(0), facts: readOrders}, err
		}},
	{"biscuit-unchecked", "Nothing to check against",
		"the healthy token with no root key, no revocation list and no authorizer. The links between blocks still verify, and the expiry checks are evaluated against the time; nothing else can be.",
		func(base time.Time) (demo, error) {
			m, err := mintAll(rootSigner, blockSigner, healthyBlocks(base))
			if err != nil {
				return demo{}, err
			}
			tok, err := m.Token()
			return demo{tok: tok, root: rootSigner, noRootKey: true, noRevoke: true, noAuth: true}, err
		}},
}

// encodeBlockAt encodes a replacement for block i of tok, with the symbols
// the token already has, as an editor of the token would.
func encodeBlockAt(spec BlockSpec, tok *Token, i int) ([]byte, uint32, error) {
	syms := datalog.NewSymbolTable()
	for _, b := range tok.Blocks[:i] {
		pbb, err := datalog.DecodeBlock(b.Data)
		if err != nil {
			return nil, 0, err
		}
		if err := syms.Extend(pbb.GetSymbols()); err != nil {
			return nil, 0, err
		}
	}
	return encodeBlock(spec, syms, datalog.MinVersion)
}

func (d demo) options() (Options, error) {
	o := Options{Limits: datalog.DefaultLimits}
	if !d.noRootKey {
		o.RootKeys = []Key{d.root.Pub}
		o.RootSources = []string{"demo root key"}
	}
	if !d.noRevoke {
		o.Revoked = map[string]bool{}
		for _, id := range d.revoked {
			o.Revoked[id] = true
		}
		o.RevokedSource = "demo revocation list"
	}
	if !d.noAuth {
		src := strings.Join(d.facts, ";\n") + ";\n"
		p, err := datalog.ParseProgram(src + d.policyOr() + ";\n")
		if err != nil {
			return o, err
		}
		o.Program, o.HasAuthorizer = p, true
		o.AuthorizerSource = "demo: " + strings.Join(d.facts, ", ")
	}
	return o, nil
}

func (d demo) policyOr() string {
	if d.policy != "" {
		return d.policy
	}
	return "allow if true"
}

// Scenarios are Biscuit's demos.
func (Adapter) Scenarios() []chain.Scenario {
	var out []chain.Scenario
	for _, sp := range specs {
		sp := sp
		out = append(out, chain.Scenario{
			Name: sp.name, Title: sp.title, Summary: sp.summary, Format: ID,
			Open: func(base time.Time) (chain.Session, error) {
				d, err := sp.build(base)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", sp.name, err)
				}
				opts, err := d.options()
				if err != nil {
					return nil, err
				}
				return &Session{tok: d.tok, opts: opts, at: base.Add(time.Minute), source: sp.name}, nil
			},
			Emit: func(dir string, force bool) (string, error) {
				return emit(sp, dir, force)
			},
		})
	}
	return out
}

// emitBase is the time emitted fixtures are minted at, so they are the
// same bytes on every run; the command they come with evaluates them just
// after it.
var emitBase = time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)

func emit(sp spec, dir string, force bool) (string, error) {
	d, err := sp.build(emitBase)
	if err != nil {
		return "", err
	}
	text, err := d.tok.Text()
	if err != nil {
		return "", err
	}
	if err := safewrite.Dir(dir, force); err != nil {
		return "", err
	}
	files := map[string][]byte{
		"token.b64": []byte(Prefix + text + "\n"),
	}
	args := []string{"whosent check token.b64 --format biscuit"}
	if !d.noRootKey {
		files["root.pub"] = []byte(d.root.Pub.String() + "\n")
		args = append(args, "--root-key root.pub")
	}
	if !d.noAuth {
		files["authorizer.datalog"] = []byte(strings.Join(d.facts, ";\n") + ";\n\n" + d.policyOr() + ";\n")
		args = append(args, "--authorizer authorizer.datalog")
	}
	if !d.noRevoke {
		var ids strings.Builder
		ids.WriteString("# revoked Biscuit revocation ids, one per line\n")
		for _, id := range d.revoked {
			ids.WriteString(id + "\n")
		}
		files["revoked-ids.txt"] = []byte(ids.String())
		args = append(args, "--revoked-jtis revoked-ids.txt")
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
