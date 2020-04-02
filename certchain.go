package certificate_searcher

import (
	"github.com/teamnsrg/zcrypto/x509"
	"github.com/teamnsrg/zlint"
)

type LogTimestamp struct {
	Log       string `json:"log,omitempty"`
	Timestamp int    `json:"timestamp,omitempty"`
}

type CertChain struct {
	Leaf                       *x509.JSONCertificate `json:"leaf,omitempty"`
	LeafParent                 *x509.JSONCertificate `json:"leaf_parent,omitempty"`
	Root                       *x509.JSONCertificate `json:"root,omitempty"`
	ChainDepth                 int               `json:"chain_depth,omitempty"`
	NssTrusted                 bool              `json:"nss_trusted,omitempty"`
	AppleTrusted               bool              `json:"apple_trusted,omitempty"`
	MicrosoftTrusted           bool              `json:"microsoft_trusted,omitempty"`
	ValidationLevel            string            `json:"validation_level,omitempty"`
	LeafValidLength            int               `json:"leaf_valid_len,omitempty"`
	CTLogTimestamps            []LogTimestamp    `json:"ct_log_timestamps,omitempty"`
	LogTimestamp               string            `json:"min_ct_log_timestamp,omitempty"`
	LeafAsn1Fingerprint        string            `json:"leaf_asn1_fp_no_subj_no_ext,omitempty"`
	LeafAsn1FingerprintExt     string            `json:"leaf_asn1_fp_no_subj_yes_ext,omitempty"`
	LeafAsn1FingerprintSubj    string            `json:"leaf_asn1_fp_yes_subj_no_ext,omitempty"`
	LeafAsn1FingerprintSubjExt string            `json:"leaf_asn1_fp_yes_subj_yes_ext,omitempty"`
	MatchedDomains             string            `json:"matched_domains,omitempty"`
	ZLintResult                *zlint.ResultSet  `json:"zlint_result,omitempty"`
}

