package main

import (
	"encoding/hex"
	"fmt"
	"os"

	ecvrf "github.com/tikaydaes/ecvrf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ecvrf-cli prove <sk_hex> <alpha_hex> | verify <pk_hex> <pi_hex> <alpha_hex> | derive-pk <sk_hex>")
		os.Exit(2)
	}
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return b
	}
	switch os.Args[1] {
	case "prove":
		pi, err := ecvrf.Prove(mustHex(os.Args[2]), mustHex(os.Args[3]))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(pi))
	case "verify":
		ok, beta := ecvrf.Verify(mustHex(os.Args[2]), mustHex(os.Args[3]), mustHex(os.Args[4]))
		if !ok {
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(beta))
	case "derive-pk":
		pk, err := ecvrf.DerivePublicKey(mustHex(os.Args[2]))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(pk))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}
