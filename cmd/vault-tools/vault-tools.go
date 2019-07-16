package main

import (
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/richardfelkl/vault-tools-go/pkg/vault"

	vaultapi "github.com/hashicorp/vault/api"
)

func main() {
	if len(os.Args) == 1 {
		log.Printf("ERROR: %v\n", "The command name must be provided")
	}
	switch os.Args[1] {
	case "csr":
		runCsr()
	default:
		log.Printf("ERROR: %v\n", "Unknown command name")
	}
}

func runCsr() {
	var vaultAddress, vaultToken, name, names string
	mySet := flag.NewFlagSet("", flag.ExitOnError)
	mySet.StringVar(&vaultToken, "token", "", "Vault token")
	mySet.StringVar(&vaultAddress, "address", "http://127.0.0.1:8200", "Vault address")
	mySet.StringVar(&name, "name", "", "Transit key name")
	mySet.StringVar(&names, "names", "", "CSR names JSON file location")
	mySet.Parse(os.Args[2:])

	if vaultAddress == "" {
		log.Printf("ERROR: %v\n", "Vault address has to be specified.")
		return
	}
	if vaultToken == "" {
		log.Printf("ERROR: %v\n", "Vault token has to be specified.")
		return
	}
	if name == "" {
		log.Printf("ERROR: %v\n", "Vault transit name has to be specified.")
		return
	}
	if names == "" {
		log.Printf("ERROR: %v\n", "CSR names JSON file location has to be specified.")
		return
	}

	if os.Getenv("VAULT_TOKEN") != "" {
		vaultToken = os.Getenv("VAULT_TOKEN")
	}
	if os.Getenv("VAULT_ADDR") != "" {
		vaultAddress = os.Getenv("VAULT_ADDR")
	}

	manager, _ := vault.GetManager(vaultToken, &vaultapi.Config{Address: vaultAddress})
	pkixName, _ := parsePkixName(names)
	result, err := manager.TransitCreateCSR(name, *pkixName)
	if err != nil {
		log.Printf("ERROR: %v\n", err.Error())
		return
	}
	fmt.Printf("CSR:\n%v\n", result)
}

func parsePkixName(path string) (*pkix.Name, error) {
	pkixName := &pkix.Name{}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("ERROR: File reading %v", err.Error())
		return nil, err
	}

	err = json.Unmarshal(data, pkixName)

	return pkixName, nil
}
