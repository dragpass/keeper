package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
)

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(dispatch.RegisteredActionNames()); err != nil {
		log.Fatal(err)
	}
}
