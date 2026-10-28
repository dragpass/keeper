package keychain

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
)

type claimWriteFault struct {
	SecretStore
	armed bool
}

func (s *claimWriteFault) Set(service, account, value string) error {
	if strings.HasPrefix(account, "chat_claim_v1_") && s.armed {
		s.armed = false
		if err := s.SecretStore.Set(service, account, value); err != nil {
			return err
		}
		return errors.New("lost write answer")
	}
	return s.SecretStore.Set(service, account, value)
}

func TestChatClaimHighWaterSurvivesLostWriteAnswer(t *testing.T) {
	store := NewMemorySecretStore()
	if err := saveChatLogin(store, ChatLoginState{Generation: "AAAAAAAAAAAAAAAAAAAAAA"}); err != nil {
		t.Fatal(err)
	}
	fault := &claimWriteFault{SecretStore: store, armed: true}
	if err := ConsumeChatClaim(fault, "AAAAAAAAAAAAAAAAAAAAAA", "holder", 2); err == nil {
		t.Fatal("uncertain write admitted claim")
	}
	if err := ConsumeChatClaim(store, "AAAAAAAAAAAAAAAAAAAAAA", "holder", 2); !errors.Is(err, ErrChatLoginStale) {
		t.Fatal("equal replay admitted")
	}
	if err := ConsumeChatClaim(store, "AAAAAAAAAAAAAAAAAAAAAA", "holder", 1); !errors.Is(err, ErrChatLoginStale) {
		t.Fatal("older replay admitted")
	}
	if err := ConsumeChatClaim(store, "AAAAAAAAAAAAAAAAAAAAAA", "holder", 3); err != nil {
		t.Fatal("fresh sequence refused")
	}
	for key := range store.Snapshot() {
		if strings.Contains(key, "chat_claim_v1_") {
			account := strings.TrimPrefix(key, config.Service+"|")
			for _, bad := range []string{"0", "02", "-1", "garbage", "9007199254740992"} {
				_ = store.Set(config.Service, account, bad)
				if err := ConsumeChatClaim(store, "AAAAAAAAAAAAAAAAAAAAAA", "holder", 4); err == nil {
					t.Fatal("corrupt high-water reset")
				}
			}
		}
	}
}
