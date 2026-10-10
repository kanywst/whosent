package biscuit

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/internal/formats/biscuit/pb"
)

// Prefix marks a token in text when nothing else says it is a Biscuit.
const Prefix = "biscuit:"

// MaxBlocks is the most blocks whosent reads. Real tokens have a handful;
// the cap keeps a hostile input from making the view and the engine do
// unbounded work.
const MaxBlocks = 32

// MaxBlockSize bounds one block's serialized Datalog.
const MaxBlockSize = 256 << 10

// Encoding says how the token was handed over.
type Encoding string

// The encodings whosent reads.
const (
	EncBase64 Encoding = "base64url"
	EncRaw    Encoding = "protobuf"
)

// SignedBlock is one block as it travels: serialized Datalog, the key the
// next block is signed with, and this block's signature.
type SignedBlock struct {
	Data      []byte
	NextKey   datalog.PublicKey
	Signature []byte
	External  *ExternalSig
	// Version is the signature payload version; HasVersion tells an
	// explicit 0 apart from none.
	Version    uint32
	HasVersion bool
}

// ExternalSig is a third party's signature over a block.
type ExternalSig struct {
	Signature []byte
	Key       datalog.PublicKey
}

// Token is a decoded Biscuit, not yet verified.
type Token struct {
	RootKeyID *uint32
	// Blocks holds the authority block first.
	Blocks []SignedBlock
	// Proof: exactly one of NextSecret and FinalSignature is set for a
	// well-formed token; neither when the proof is missing.
	NextSecret     []byte
	FinalSignature []byte
	HasProof       bool
	Encoding       Encoding
	Size           int
	// Normalizations says what was done to the text before decoding.
	Normalizations []string
}

// Sealed reports whether the token carries a final signature instead of
// the last private key, so no block can be appended.
func (t *Token) Sealed() bool { return t.FinalSignature != nil }

// LooksLikeText reports whether data is the token's text form, possibly
// prefixed: base64url characters only, after trimming.
func looksLikeText(data []byte) (string, bool) {
	s := strings.TrimSpace(string(data))
	s = strings.TrimPrefix(s, Prefix)
	if s == "" {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !base64urlChar(c) {
			return "", false
		}
	}
	return s, true
}

func base64urlChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '='
}

// decodeText decodes base64url, padded or not. The reference writes it
// padded and reads it padded; reading both costs nothing and is what a
// person pasting a token expects.
func decodeText(s string) ([]byte, error) {
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Decode reads a token from its text form (base64url, optionally prefixed
// "biscuit:") or from raw protobuf bytes.
func Decode(data []byte) (*Token, error) {
	var raw []byte
	tok := &Token{}
	if s, ok := looksLikeText(data); ok {
		b, err := decodeText(s)
		if err != nil {
			return nil, fmt.Errorf("the token is not valid base64url: %w", err)
		}
		raw = b
		tok.Encoding = EncBase64
		trimmed := strings.TrimSpace(string(data))
		if trimmed != string(data) {
			tok.Normalizations = append(tok.Normalizations, "surrounding whitespace removed")
		}
		if strings.HasPrefix(trimmed, Prefix) {
			tok.Normalizations = append(tok.Normalizations, `"biscuit:" prefix removed`)
		}
	} else {
		raw = data
		tok.Encoding = EncRaw
	}
	tok.Size = len(raw)
	var b pb.Biscuit
	if err := (proto.UnmarshalOptions{AllowPartial: true}).Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("the token is not a Biscuit: %w", err)
	}
	if b.Authority == nil {
		return nil, errors.New("the token is not a Biscuit: it has no authority block")
	}
	if len(b.Blocks)+1 > MaxBlocks {
		return nil, fmt.Errorf("the token has %d blocks; whosent reads at most %d", len(b.Blocks)+1, MaxBlocks)
	}
	tok.RootKeyID = b.RootKeyId
	for i, sb := range append([]*pb.SignedBlock{b.Authority}, b.Blocks...) {
		if len(sb.GetBlock()) > MaxBlockSize {
			return nil, fmt.Errorf("block %d is %d bytes; whosent reads blocks of at most %d", i, len(sb.GetBlock()), MaxBlockSize)
		}
		blk := SignedBlock{
			Data:       sb.GetBlock(),
			NextKey:    datalog.KeyFromProto(sb.GetNextKey()),
			Signature:  sb.GetSignature(),
			Version:    sb.GetVersion(),
			HasVersion: sb.Version != nil,
		}
		if es := sb.GetExternalSignature(); es != nil {
			blk.External = &ExternalSig{Signature: es.GetSignature(), Key: datalog.KeyFromProto(es.GetPublicKey())}
		}
		tok.Blocks = append(tok.Blocks, blk)
	}
	if p := b.GetProof(); p != nil {
		switch c := p.GetContent().(type) {
		case *pb.Proof_NextSecret:
			tok.NextSecret, tok.HasProof = c.NextSecret, true
		case *pb.Proof_FinalSignature:
			tok.FinalSignature, tok.HasProof = c.FinalSignature, true
		}
	}
	return tok, nil
}

// Encode serializes a token, for minting.
func (t *Token) Encode() ([]byte, error) {
	b := &pb.Biscuit{RootKeyId: t.RootKeyID, Proof: &pb.Proof{}}
	for i, blk := range t.Blocks {
		sb := &pb.SignedBlock{
			Block:     blk.Data,
			NextKey:   datalog.KeyToProto(blk.NextKey),
			Signature: blk.Signature,
		}
		if blk.HasVersion || blk.Version != 0 {
			sb.Version = proto.Uint32(blk.Version)
		}
		if blk.External != nil {
			sb.ExternalSignature = &pb.ExternalSignature{Signature: blk.External.Signature, PublicKey: datalog.KeyToProto(blk.External.Key)}
		}
		if i == 0 {
			b.Authority = sb
		} else {
			b.Blocks = append(b.Blocks, sb)
		}
	}
	switch {
	case t.FinalSignature != nil:
		b.Proof.Content = &pb.Proof_FinalSignature{FinalSignature: t.FinalSignature}
	default:
		b.Proof.Content = &pb.Proof_NextSecret{NextSecret: t.NextSecret}
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(b)
}

// Text is the token's text form, padded base64url as the reference writes.
func (t *Token) Text() (string, error) {
	raw, err := t.Encode()
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(raw), nil
}

// looksLikeBiscuit is detection's cheap structural test: the bytes decode
// as a Biscuit message whose authority block carries Datalog, a next key
// and a signature, and a proof.
func looksLikeBiscuit(raw []byte) bool {
	var b pb.Biscuit
	if err := (proto.UnmarshalOptions{AllowPartial: true}).Unmarshal(raw, &b); err != nil {
		return false
	}
	a := b.GetAuthority()
	if a == nil || len(a.GetBlock()) == 0 || a.GetNextKey() == nil || len(a.GetSignature()) == 0 || b.GetProof() == nil {
		return false
	}
	// A Datalog block must decode too, or this is some other message that
	// happens to share field numbers.
	_, err := datalog.DecodeBlock(a.GetBlock())
	return err == nil && !bytes.Equal(raw, nil)
}
