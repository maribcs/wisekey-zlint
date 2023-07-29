package ct

import (
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"time"

	"wisekey-zlint/ctpolicy/loglist"
	"wisekey-zlint/linter/lints"
)

type sctsFromSameOperator struct {
	// TODO check: maybe we should filter the logs by their state here, e.g. only usable. Check if this is already being done.
	logList loglist.List
}

func init() {
	lint.RegisterLint(&lint.Lint{
		// TODO evaluate to create multiple lints for checking Chrome CT policy compliance instead of a single one checking multiple things.
		Name:          "e_embedded_scts_chrome_ct_policy",
		Description:   "Subscriber Certificates have to comply with Chrome CT policy",
		Citation:      "Chrome CT Policy",
		Source:        lints.ChromeCTPolicy,
		EffectiveDate: time.Date(2022, time.April, 15, 0, 0, 0, 0, time.UTC),
		Lint:          NewSCTsFromSameOperator,
	})
}

func NewSCTsFromSameOperator() lint.LintInterface {
	return &sctsFromSameOperator{logList: loglist.GetLintList()}
}

func (l *sctsFromSameOperator) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !util.IsExtInCert(c, util.CtPoisonOID)
}

func (l *sctsFromSameOperator) Execute(c *x509.Certificate) *lint.LintResult {
	if len(l.logList) == 0 {
		return &lint.LintResult{
			Status:  lint.NE,
			Details: "Failed to load log list, unable to check Certificate SCTs.",
		}
	}

	// Copied from https://github.com/zmap/zlint/blob/a5c869f807cbfce8a689aeba5682eb8f326845ea/v3/lints/apple/lint_e_server_cert_valid_time_longer_than_398_days.go#L54
	certValidity := c.NotAfter.Add(1 * time.Second).Sub(c.NotBefore)

	var minimumSCTs int
	if certValidity <= 180*lints.BRDay {
		minimumSCTs = 2
	} else {
		minimumSCTs = 3
	}

	if len(c.SignedCertificateTimestampList) < minimumSCTs {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Certificate had too few embedded SCTs; browser policy requires %d.", minimumSCTs),
		}
	}

	logIDs := make(map[ct.SHA256Hash]struct{})
	for _, sct := range c.SignedCertificateTimestampList {
		logIDs[sct.LogID] = struct{}{}
	}

	if len(logIDs) < minimumSCTs {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Certificate SCTs from too few distinct logs; browser policy requires %d.", minimumSCTs),
		}
	}

	operatorNames := make(map[string]struct{})
	for logID := range logIDs {
		operator, err := l.logList.OperatorForLogID(logID.Base64String())
		if err != nil {
			// This certificate *may* have more than 2 SCTs, so missing one now isn't
			// a problem.
			continue
		}
		operatorNames[operator] = struct{}{}
	}

	if len(operatorNames) < 2 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Certificate SCTs from too few distinct log operators; browser policy requires 2.",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
