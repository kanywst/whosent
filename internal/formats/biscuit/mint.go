package biscuit

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
)

// Minter builds tokens, for the demos and the tests. It signs as the
// reference's builder does, including its choice of signature payload
// version, so a minted token is one the reference would also produce.
type Minter struct {
	tok      *Token
	syms     *datalog.SymbolTable
	next     Signer
	versions []uint32
}

// BlockSpec is one block to mint.
type BlockSpec struct {
	// Source is the block's Datalog, optionally starting with a
	// "trusting ...;" annotation.
	Source string
	// Context is the block's free-form context string, when set.
	Context string
}

func signatureVersion(signer, next Signer, external bool, datalogVersion uint32, previous []uint32) uint32 {
	if external {
		return 1
	}
	if datalogVersion >= datalog.Version33 {
		return 1
	}
	if signer.Pub.Alg != datalog.Ed25519 || next.Pub.Alg != datalog.Ed25519 {
		return 1
	}
	var v uint32
	for _, p := range previous {
		v = max(v, p)
	}
	return v
}

func encodeBlock(spec BlockSpec, syms *datalog.SymbolTable, minVersion uint32) ([]byte, uint32, error) {
	parsed, err := datalog.ParseBlock(spec.Source)
	if err != nil {
		return nil, 0, err
	}
	version := max(datalog.SchemaVersion(parsed), minVersion)
	symBefore, keysBefore := syms.Len(), len(syms.Keys())
	b := datalog.ConvertBlock(parsed, syms)
	b.Version = version
	if spec.Context != "" {
		b.Context, b.HasContext = spec.Context, true
	}
	newSyms := syms.Strings()[symBefore:]
	newKeys := syms.Keys()[keysBefore:]
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(datalog.ToProto(b, newSyms, newKeys))
	if err != nil {
		return nil, 0, err
	}
	return data, version, nil
}

// Mint starts a token: the authority block, signed by root.
func Mint(root, next Signer, spec BlockSpec) (*Minter, error) {
	syms := datalog.NewSymbolTable()
	data, dv, err := encodeBlock(spec, syms, datalog.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("authority block: %w", err)
	}
	sv := signatureVersion(root, next, false, dv, nil)
	var payload []byte
	if sv == 1 {
		payload = payloadAuthorityV1(data, next.Pub.PublicKey, sv)
	} else {
		payload = payloadV0(data, next.Pub.PublicKey, nil)
	}
	sig, err := root.Sign(payload)
	if err != nil {
		return nil, err
	}
	m := &Minter{
		tok:      &Token{Blocks: []SignedBlock{{Data: data, NextKey: next.Pub.PublicKey, Signature: sig, Version: sv, HasVersion: sv > 0}}},
		syms:     syms,
		next:     next,
		versions: []uint32{sv},
	}
	return m, nil
}

// Append adds a first-party block, signed with the last block's next key.
func (m *Minter) Append(next Signer, spec BlockSpec) error {
	data, dv, err := encodeBlock(spec, m.syms, datalog.MinVersion)
	if err != nil {
		return fmt.Errorf("block %d: %w", len(m.tok.Blocks), err)
	}
	return m.appendSigned(next, data, dv, nil)
}

// AppendThirdParty adds a block signed by a third party as well, with its
// own symbol table, as a third-party block must be.
func (m *Minter) AppendThirdParty(next, third Signer, spec BlockSpec) error {
	own := datalog.NewSymbolTable()
	data, dv, err := encodeBlock(spec, own, datalog.Version32)
	if err != nil {
		return fmt.Errorf("block %d: %w", len(m.tok.Blocks), err)
	}
	prev := m.tok.Blocks[len(m.tok.Blocks)-1]
	esig, err := third.Sign(payloadExternalV1(data, prev.Signature, 1))
	if err != nil {
		return err
	}
	return m.appendSigned(next, data, dv, &ExternalSig{Signature: esig, Key: third.Pub.PublicKey})
}

func (m *Minter) appendSigned(next Signer, data []byte, dv uint32, ext *ExternalSig) error {
	prev := m.tok.Blocks[len(m.tok.Blocks)-1]
	sv := signatureVersion(m.next, next, ext != nil, dv, m.versions)
	var extSig []byte
	if ext != nil {
		extSig = ext.Signature
	}
	var payload []byte
	if sv == 1 {
		payload = payloadBlockV1(data, next.Pub.PublicKey, extSig, prev.Signature, sv)
	} else {
		payload = payloadV0(data, next.Pub.PublicKey, extSig)
	}
	sig, err := m.next.Sign(payload)
	if err != nil {
		return err
	}
	m.tok.Blocks = append(m.tok.Blocks, SignedBlock{Data: data, NextKey: next.Pub.PublicKey, Signature: sig, External: ext, Version: sv, HasVersion: sv > 0})
	m.versions = append(m.versions, sv)
	m.next = next
	return nil
}

// Token finishes an open token: its proof is the last private key.
func (m *Minter) Token() (*Token, error) {
	secret, err := m.next.Secret()
	if err != nil {
		return nil, err
	}
	t := *m.tok
	t.Blocks = append([]SignedBlock(nil), m.tok.Blocks...)
	t.NextSecret, t.HasProof = secret, true
	return &t, nil
}

// Sealed finishes a sealed token: its proof is a signature over the last
// block, so nothing can be appended.
func (m *Minter) Sealed() (*Token, error) {
	if len(m.tok.Blocks) == 0 {
		return nil, errors.New("nothing to seal")
	}
	last := m.tok.Blocks[len(m.tok.Blocks)-1]
	sig, err := m.next.Sign(payloadSeal(last.Data, last.NextKey, last.Signature))
	if err != nil {
		return nil, err
	}
	t := *m.tok
	t.Blocks = append([]SignedBlock(nil), m.tok.Blocks...)
	t.FinalSignature, t.HasProof = sig, true
	return &t, nil
}
