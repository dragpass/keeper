// roomname.go — a v2 room's name, sealed under a key the epoch's MLS exporter
// derives.
//
// The server keeps a room's name as name_iv / name_ciphertext and never sees
// the plaintext, in v1 and in v2 alike. In v2 the key is
//
//	MLS-Exporter("dragpass room name", conversation_id, 32)
//
// of one epoch (RFC 9420 §8.5): every member of that epoch derives it, nobody
// outside does, and it changes with every Commit. So every Commit that moves a
// room's epoch carries the name resealed for the epoch it creates, and the
// committer computes that before the server's CAS, from the pending Commit and
// without applying it. A name is opened only for the confirmed epoch: an older
// epoch's exporter is gone once the group has left it, which is the forward
// secrecy the exporter is for.
//
// Accepted gap: the server cannot tell a reseal from a rename. A member with a
// modified client can put any name into a Commit it builds, and every member
// will open it. Normal clients reseal the name they have just opened.

package chatstate

import (
	"crypto/rand"
	"errors"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/secure"
)

const (
	// RoomNameExporterLabel is the exporter label. The context is the
	// conversation id's bytes, so two rooms' names in one epoch never share a
	// key.
	RoomNameExporterLabel = "dragpass room name"
	RoomNameKeyBytes      = 32

	// MaxRoomNameBytes matches the server's name_ciphertext column, 272
	// bytes of ciphertext and tag.
	MaxRoomNameBytes = 256

	roomNameAADDomain  = "dragpass.room.name"
	roomNameAADVersion = 1
)

// ErrRoomNameUnopenable — the name did not open under this epoch's key: it was
// sealed for another conversation or epoch, or it was altered.
var ErrRoomNameUnopenable = errors.New("chat state could not open the room name for this epoch")

// RoomNameExporter reads the exporter of the confirmed epoch, and of the epoch
// a pending Commit would create without applying it.
type RoomNameExporter interface {
	ExportSecret(label, context []byte, n int) ([]byte, error)
	ExportPendingSecret(label, context []byte, n int) ([]byte, uint64, error)
}

// RoomNameCipher is what sealing or opening a name under the confirmed epoch
// needs.
type RoomNameCipher interface {
	Load(groupState []byte) error
	Epoch() (uint64, error)
	RoomNameExporter
}

// SealedRoomName is the server's name_iv / name_ciphertext and the epoch whose
// exporter opens it.
type SealedRoomName struct {
	Epoch      uint64
	IV         []byte
	Ciphertext []byte
}

// RoomNameAAD is dragpass.room.name|1|<conversation_id>|<epoch>.
func RoomNameAAD(conversationID string, epoch uint64) []byte {
	return []byte(strings.Join([]string{
		roomNameAADDomain,
		strconv.Itoa(roomNameAADVersion),
		conversationID,
		strconv.FormatUint(epoch, 10),
	}, "|"))
}

func validRoomName(name []byte) error {
	if len(name) == 0 || len(name) > MaxRoomNameBytes {
		return errors.New("room name is outside 1..256 bytes")
	}
	return nil
}

func sealRoomName(key []byte, conversationID string, epoch uint64, name []byte) (SealedRoomName, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return SealedRoomName{}, err
	}
	iv := make([]byte, ivBytes)
	if _, err := rand.Read(iv); err != nil {
		return SealedRoomName{}, err
	}
	return SealedRoomName{
		Epoch:      epoch,
		IV:         iv,
		Ciphertext: gcm.Seal(nil, iv, name, RoomNameAAD(conversationID, epoch)),
	}, nil
}

// sealForPending reseals name for the epoch the loaded pending Commit creates,
// and checks that epoch is the one after the Commit's base.
func sealForPending(cipher RoomNameExporter, conversationID string, base uint64, name []byte) (*SealedRoomName, error) {
	key, epoch, err := cipher.ExportPendingSecret([]byte(RoomNameExporterLabel), []byte(conversationID), RoomNameKeyBytes)
	defer secure.Zeroize(key)
	if err != nil {
		return nil, err
	}
	if epoch != base+1 {
		return nil, errors.New("the pending commit does not create the epoch after its base")
	}
	sealed, err := sealRoomName(key, conversationID, epoch, name)
	if err != nil {
		return nil, err
	}
	return &sealed, nil
}

// SealRoomName seals a name under the confirmed epoch's exporter, for a rename
// or a room's first name. Nothing is written. A pending Commit of this device
// does not refuse it: a create's epoch 0 name is sealed this way while the
// create is pending, and the Commit carries its own reseal for the next epoch.
func (s *Store) SealRoomName(
	conversationID string, wm ServerWatermark, name []byte, cipher RoomNameCipher,
) (SealedRoomName, error) {
	if err := validRoomName(name); err != nil {
		return SealedRoomName{}, err
	}
	var out SealedRoomName
	err := s.withRoomNameKey(conversationID, wm, cipher, func(key []byte, epoch uint64) error {
		var err error
		out, err = sealRoomName(key, conversationID, epoch, name)
		return err
	})
	return out, err
}

// OpenRoomName opens a name sealed for epoch, which must be the confirmed one:
// ErrEpochStale otherwise, before any key is derived. The plaintext is the
// caller's to wipe. Nothing is written.
func (s *Store) OpenRoomName(
	conversationID string, wm ServerWatermark, epoch uint64, iv, ciphertext []byte, cipher RoomNameCipher,
) ([]byte, error) {
	if len(iv) != ivBytes {
		return nil, ErrRoomNameUnopenable
	}
	var out []byte
	err := s.withRoomNameKey(conversationID, wm, cipher, func(key []byte, confirmed uint64) error {
		if confirmed != epoch {
			return ErrEpochStale
		}
		gcm, err := newGCM(key)
		if err != nil {
			return err
		}
		if out, err = gcm.Open(nil, iv, ciphertext, RoomNameAAD(conversationID, epoch)); err != nil {
			return ErrRoomNameUnopenable
		}
		return nil
	})
	return out, err
}

// withRoomNameKey derives the confirmed epoch's name key under the
// conversation lock and wipes it afterwards.
func (s *Store) withRoomNameKey(
	conversationID string, wm ServerWatermark, cipher RoomNameCipher, use func(key []byte, epoch uint64) error,
) error {
	return s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		epoch, err := cipher.Epoch()
		if err != nil {
			return err
		}
		key, err := cipher.ExportSecret([]byte(RoomNameExporterLabel), []byte(conversationID), RoomNameKeyBytes)
		defer secure.Zeroize(key)
		if err != nil {
			return err
		}
		return use(key, epoch)
	})
}
