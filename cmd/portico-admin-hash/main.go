// Command portico-admin-hash derives a password verifier for a Kubernetes Secret.
// Supply the password on stdin; it is never accepted as a command-line argument.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"portico-gateway/internal/adminauth"
	"strings"
)

func main() {
	input, err := io.ReadAll(io.LimitReader(bufio.NewReader(os.Stdin), 1026))
	if err != nil || len(input) > 1025 {
		fmt.Fprintln(os.Stderr, "unable to read password")
		os.Exit(1)
	}
	password := strings.TrimSuffix(string(input), "\n")
	password = strings.TrimSuffix(password, "\r")
	hash, err := adminauth.HashLocalPassword(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
