// declaration.go — the chain position a sender declares inside the message it
// sends, and the check a receiver runs against it.
//
// The declaration rides in the MLS `authenticated_data` field, which is
// cleartext on the wire and covered twice: the sender signs FramedContent,
// which contains it, and the AEAD binds it through PrivateContentAAD. A server
// that edits it breaks the signature before it breaks the tag. Put in an
// ordinary request field instead it would be the server's word.
//
// The receiver compares the declaration against the generation the library
// really derived its keys from. Upstream recommends exactly this against
// in-group forgery (eprint 2025/554); design §7.4 uses the same value for a
// second purpose and is careful to claim only what it buys.

package chatstate

import (
	"errors"
	"strconv"
	"strings"
)

const (
	declarationDomain  = "dragpass.chat.mls"
	declarationVersion = "1"
	declarationFields  = 5
)

// Sentinels for the two ways a declaration fails. They are separate because
// "the sender said something else" and "nothing could be compared" are
// different findings, even though both end the same way: no plaintext.
var (
	// ErrGenerationUnknown — the library answered None for the generation it
	// decrypted with. Upstream reaches None by swallowing an extraction error
	// into a default, so this is "could not look", not "looked and saw zero".
	ErrGenerationUnknown = errors.New("chat state cannot verify the generation of an inbound message")

	// ErrDeclarationMismatch — the sender's declaration and the position the
	// message actually occupies disagree, or there was no declaration to
	// compare against.
	ErrDeclarationMismatch = errors.New("chat state inbound declaration does not match the message")
)

// axis is the one-letter name of a sender's two ratchets. Short because it is
// on the wire of every message.
func (c ContentType) axis() string {
	switch c {
	case ContentTypeHandshake:
		return "h"
	case ContentTypeApplication:
		return "a"
	default:
		return ""
	}
}

func contentTypeFromAxis(axis string) ContentType {
	switch axis {
	case "h":
		return ContentTypeHandshake
	case "a":
		return ContentTypeApplication
	default:
		return ""
	}
}

// declaration renders the three slots a receiver cannot read off the cleartext
// framing. The epoch is left out on purpose: PrivateMessage already carries it
// in the clear and the AEAD already binds it, so repeating it here would add a
// second copy that could disagree with the first.
func (p Position) declaration() []byte {
	return []byte(strings.Join([]string{
		declarationDomain,
		declarationVersion,
		p.ContentType.axis(),
		strconv.FormatUint(uint64(p.SenderLeafIndex), 10),
		strconv.FormatUint(p.Generation, 10),
	}, "|"))
}

// verifyDeclaration refuses everything it cannot match. Three rules, and none
// of them has a lenient branch:
//
//   - A nil generation is refused rather than read as zero. Substituting a
//     default here would make "compared it" and "knew nothing" the same answer,
//     and a sender lying about its generation would pass.
//   - A missing or malformed declaration is refused. Skipping the comparison is
//     only coherent under a watermark scheme that has no declaration at all;
//     under this one a message without one is a message that cannot be checked.
//   - A mismatch is refused. There is no "deliver it with a warning" path.
func verifyDeclaration(declared []byte, actual Position, keyGeneration *uint32) error {
	if keyGeneration == nil {
		return ErrGenerationUnknown
	}
	fields := strings.Split(string(declared), "|")
	if len(fields) != declarationFields ||
		fields[0] != declarationDomain ||
		fields[1] != declarationVersion {
		return ErrDeclarationMismatch
	}
	leaf, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return ErrDeclarationMismatch
	}
	generation, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return ErrDeclarationMismatch
	}
	if contentTypeFromAxis(fields[2]) != actual.ContentType ||
		uint32(leaf) != actual.SenderLeafIndex ||
		generation != uint64(*keyGeneration) ||
		generation != actual.Generation {
		return ErrDeclarationMismatch
	}
	return nil
}
