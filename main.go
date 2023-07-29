package main

import (
	"fmt"
	zlintx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
	"os"
	"wisekey-zlint/linter/lints"

	// TODO check: in Boulder even the local references use identifiers from GitHub like "github.com/letsencrypt/boulder/ctpolicy/loglist". See https://github.com/letsencrypt/boulder/blob/c46f19faedb5a8e6d9de6daa59cadf48a6a87c12/linter/lints/chrome/e_scts_from_same_operator.go#L11 and check why.
	"wisekey-zlint/ctpolicy/loglist"
	_ "wisekey-zlint/linter/lints/ct"
)

// https://github.com/letsencrypt/boulder/blob/f7b79d07e5678177eaa2a4125ad95bc6277d6a45/linter/linter.go used as reference for this.

func main() {

	// TODO evaluate to automate download and caching of log_list.json
	loglist.InitLintList(os.Args[2])

	// NOTE that it is currently expecting DER only
	certBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cert, err := zlintx509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	reg, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		IncludeSources: []lint.LintSource{
			lints.ChromeCTPolicy,
		},
	})

	lintRes := zlint.LintCertificateEx(cert, reg)
	results := lintRes.Results
	for lintName, result := range results {
		fmt.Println(lintName, result.Status, result.Details)
	}
	for _, result := range results {
		if result.Status != lint.Pass {
			os.Exit(1)
		}
	}
}
