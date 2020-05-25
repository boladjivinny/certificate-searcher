package certificate_searcher

import "github.com/teamnsrg/zcrypto/x509"

type LabeledCertChain struct {
AbuseDomains    map[string]LabelsSources `json:"abuse_domains"`
Leaf            *x509.Certificate           `json:"leaf,omitempty"`
LeafParent      *x509.Certificate           `json:"leaf_parent,omitempty"`
Root            *x509.Certificate           `json:"root,omitempty"`
ChainDepth      int                         `json:"chain_depth,omitempty"`
ValidationLevel string                      `json:"validation_level,omitempty"`
LeafValidLength int                         `json:"leaf_valid_len,omitempty"`
MatchedDomains  string                      `json:"matched_domains,omitempty"`
}