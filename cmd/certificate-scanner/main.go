package main

import (
	"bufio"
	"encoding/asn1"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"github.com/pkg/profile"
	certificate_scanner "github.com/teamnsrg/certificate-scanner"
	"github.com/teamnsrg/mwdomains"
	"github.com/teamnsrg/zcrypto/x509"
	"github.com/teamnsrg/zcrypto/x509/pkix"
	"github.com/teamnsrg/zlint"
	"github.com/teamnsrg/zlint/util"
	"github.com/zzma/asn1-fingerprint"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	fname                = flag.String("i", "", "File/directory to read from")
	suffix               = flag.String("s", ".certs", "suffix of files to read (when reading from directory)")
	recursiveDir         = flag.Bool("r", false, "Search directory recursively")
	delimiter            = flag.String("d", "|", "Input file major delimiter")
	field                = flag.Int("f", 1, "Input field number for cert")
	certChainDelimiter   = flag.String("cd", ",", "Input file cert chain delimiter")
	outputFilename       = flag.String("o", "-", "Output file for cert , default stdout")
	outputFormat         = flag.String("format", "json", "Output format, either csv or json")
	workerCount          = flag.Int("workers", runtime.NumCPU(), "Number of parallel parsers/json marshallers")
	logRotate            = flag.Bool("rotate", false, "perform log rotation")
	logSize              = flag.Int("log-size", 5000000000, "log size threshold for rotation")
	disableASN1Fp        = flag.Bool("disable-asn1-fp", false, "disable asn1 structural fp")
	appendChainField     = flag.Int("cf", 0, "field to append cert chain (optional)")
	logTimestampsField   = flag.Int("lf", 0, "field containing CT logs + timestamps, delimited by cd (cert chain delimiter (optional)")
	minLogTimestampField = flag.Int("tf", 0, "field containing earliest CT log time (optional)")
	runZlint             = flag.Bool("zlint", false, "run zlint")
	zlintOutDir          = flag.String("zlint-out", "", "directory to output zlint data - will omit zlint from json output")
	certDomainMatchField = flag.Int("cert-domain-match", 0, "field containing the domain that matches for a cert (when extracting certs)")
	memProfile           = flag.Bool("mem-profile", false, "run memory profiling")
	cpuProfile           = flag.Bool("cpu-profile", false, "run cpu profiling")
)

func extContains(exts []pkix.Extension, extOID asn1.ObjectIdentifier) bool {
	for _, a := range exts {
		if a.Id.Equal(extOID) {
			return true
		}
	}
	return false
}

func allFieldNames(iface interface{}) []string {
	names := make([]string, 0)
	ifv := reflect.ValueOf(iface)
	ift := reflect.TypeOf(iface)

	for i := 0; i < ift.NumField(); i++ {
		fieldType := ift.Field(i)
		fieldValue := ifv.Field(i)

		switch fieldValue.Kind() {
		case reflect.Struct:
			names = append(names, allFieldNames(fieldValue.Interface())...)
		default:
			names = append(names, fieldType.Tag.Get("csv"))
		}
	}

	return names
}

func allFieldStr(iface interface{}) []string {
	cValue := reflect.ValueOf(iface)
	strSlice := make([]string, 0)

	for i := 0; i < cValue.NumField(); i++ {
		fieldValue := cValue.Field(i)

		if fieldValue.Kind() == reflect.Struct {
			strSlice = append(strSlice, allFieldStr(fieldValue.Interface())...)
		} else {
			switch v := fieldValue.Interface().(type) {
			case int:
				strSlice = append(strSlice, strconv.Itoa(v))
			case string:
				strSlice = append(strSlice, v)
			case bool:
				if v {
					strSlice = append(strSlice, "true")
				} else {
					strSlice = append(strSlice, "false")
				}
			case x509.KeyUsage:
				switch v {
				case x509.KeyUsageDigitalSignature:
					strSlice = append(strSlice, "digital_signature")
				case x509.KeyUsageContentCommitment:
					strSlice = append(strSlice, "content_commitment")
				case x509.KeyUsageKeyEncipherment:
					strSlice = append(strSlice, "key_encipherment")
				case x509.KeyUsageDataEncipherment:
					strSlice = append(strSlice, "data_encipherment")
				case x509.KeyUsageKeyAgreement:
					strSlice = append(strSlice, "key_agreement")
				case x509.KeyUsageCertSign:
					strSlice = append(strSlice, "cert_signing")
				case x509.KeyUsageCRLSign:
					strSlice = append(strSlice, "crl_signing")
				case x509.KeyUsageEncipherOnly:
					strSlice = append(strSlice, "encipher_only")
				case x509.KeyUsageDecipherOnly:
					strSlice = append(strSlice, "decipher_only")
				default:
					strSlice = append(strSlice, "UNKNOWN_KEY_USAGE")
				}
			}
		}
	}

	return strSlice
}

func decodeAndParseChain(encodedCertChain []string, parser *x509.CertParser) ([]*x509.Certificate, error) {
	certChain := make([]*x509.Certificate, 0)
	for _, encodedCert := range encodedCertChain {
		certBytes, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			return nil, err
		}

		cert, err := parser.ParseCertificate(certBytes)
		if err != nil {
			log.Errorf("Unable to parse certificate %s due to %s", encodedCert, err)
			return nil, err
		}
		certChain = append(certChain, cert)
	}

	return certChain, nil
}

// exists returns whether the given file or directory exists
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), nil
}

func writeCertificates(outputCertStrings chan string, wg *sync.WaitGroup) {
	var outputFile *os.File
	var err error

	logFileCounter := 1

	if *outputFilename == "-" {
		outputFile = os.Stdout
	} else if len(*outputFilename) > 0 {
		var filename string

		if *logRotate {
			filename = *outputFilename + "." + strconv.Itoa(logFileCounter)
			logFileCounter += 1
		} else {
			filename = *outputFilename
		}
		outputFile, err = os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
	}

	w := bufio.NewWriterSize(outputFile, 4096*50000)
	outputSize := 0

	for output := range outputCertStrings {
		outputSize += len(output)
		w.WriteString(output)

		if *logRotate && outputSize > *logSize && outputFile != os.Stdout {
			w.Flush()
			outputFile.Close()

			outputFile, err = os.Create(*outputFilename + "." + strconv.Itoa(logFileCounter))
			if err != nil {
				log.Fatal(err)
			}

			w = bufio.NewWriterSize(outputFile, 4096*10000)

			logFileCounter += 1
			outputSize = 0
		}
	}

	w.Flush()
	outputFile.Close()
	wg.Done()
}

func writeZlint(outputZlintStrings chan string, wg *sync.WaitGroup) {
	var outputFile *os.File
	var err error

	logFileCounter := 1

	if len(*zlintOutDir) > 0 {
		var filename string

		if _, err := os.Stat(*zlintOutDir); os.IsNotExist(err) {
			os.MkdirAll(*zlintOutDir, os.ModePerm)
		}

		if *logRotate {
			filename = *zlintOutDir + "/zlint." + strconv.Itoa(logFileCounter)
			logFileCounter += 1
		} else {
			filename = *outputFilename + ".zlint"
		}
		outputFile, err = os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
	}

	w := bufio.NewWriterSize(outputFile, 4096*10000)
	outputSize := 0

	for output := range outputZlintStrings {
		outputSize += len(output)
		w.WriteString(output)

		if *logRotate && outputSize > *logSize && outputFile != os.Stdout {
			w.Flush()
			outputFile.Close()

			outputFile, err = os.Create(*zlintOutDir + "/zlint." + strconv.Itoa(logFileCounter))
			if err != nil {
				log.Fatal(err)
			}

			w = bufio.NewWriterSize(outputFile, 4096*10000)

			logFileCounter += 1
			outputSize = 0
		}
	}

	w.Flush()
	outputFile.Close()
	wg.Done()
}

func ZlintToString(set *zlint.ResultSet) []string {
	lints := []string{
		"ct_sct_policy_count_unsatisfied",
		"e_basic_constraints_not_critical",
		"e_ca_common_name_missing",
		"e_ca_country_name_invalid",
		"e_ca_country_name_missing",
		"e_ca_crl_sign_not_set",
		"e_ca_is_ca",
		"e_ca_key_cert_sign_not_set",
		"e_ca_key_usage_missing",
		"e_ca_key_usage_not_critical",
		"e_ca_organization_name_missing",
		"e_ca_subject_field_empty",
		"e_cab_dv_conflicts_with_locality",
		"e_cab_dv_conflicts_with_org",
		"e_cab_dv_conflicts_with_postal",
		"e_cab_dv_conflicts_with_province",
		"e_cab_dv_conflicts_with_street",
		"e_cab_iv_requires_personal_name",
		"e_cab_ov_requires_org",
		"e_cert_contains_unique_identifier",
		"e_cert_extensions_version_not_3",
		"e_cert_policy_iv_requires_country",
		"e_cert_policy_iv_requires_province_or_locality",
		"e_cert_policy_ov_requires_country",
		"e_cert_policy_ov_requires_province_or_locality",
		"e_cert_unique_identifier_version_not_2_or_3",
		"e_distribution_point_incomplete",
		"e_dnsname_bad_character_in_label",
		"e_dnsname_contains_bare_iana_suffix",
		"e_dnsname_empty_label",
		"e_dnsname_label_too_long",
		"e_dnsname_left_label_wildcard_correct",
		"e_dnsname_not_valid_tld",
		"e_dnsname_wildcard_only_in_left_label",
		"e_dsa_correct_order_in_subgroup",
		"e_dsa_improper_modulus_or_divisor_size",
		"e_dsa_params_missing",
		"e_dsa_shorter_than_2048_bits",
		"e_dsa_unique_correct_representation",
		"e_ec_improper_curves",
		"e_ev_business_category_missing",
		"e_ev_country_name_missing",
		"e_ev_organization_name_missing",
		"e_ev_serial_number_missing",
		"e_ev_valid_time_too_long",
		"e_ext_aia_marked_critical",
		"e_ext_authority_key_identifier_critical",
		"e_ext_authority_key_identifier_missing",
		"e_ext_authority_key_identifier_no_key_identifier",
		"e_ext_cert_policy_disallowed_any_policy_qualifier",
		"e_ext_cert_policy_duplicate",
		"e_ext_cert_policy_explicit_text_ia5_string",
		"e_ext_cert_policy_explicit_text_too_long",
		"e_ext_duplicate_extension",
		"e_ext_freshest_crl_marked_critical",
		"e_ext_ian_dns_not_ia5_string",
		"e_ext_ian_empty_name",
		"e_ext_ian_no_entries",
		"e_ext_ian_rfc822_format_invalid",
		"e_ext_ian_space_dns_name",
		"e_ext_ian_uri_format_invalid",
		"e_ext_ian_uri_host_not_fqdn_or_ip",
		"e_ext_ian_uri_not_ia5",
		"e_ext_ian_uri_relative",
		"e_ext_key_usage_cert_sign_without_ca",
		"e_ext_key_usage_without_bits",
		"e_ext_name_constraints_not_critical",
		"e_ext_name_constraints_not_in_ca",
		"e_ext_policy_constraints_empty",
		"e_ext_policy_constraints_not_critical",
		"e_ext_policy_map_any_policy",
		"e_ext_san_contains_reserved_ip",
		"e_ext_san_directory_name_present",
		"e_ext_san_dns_name_too_long",
		"e_ext_san_dns_not_ia5_string",
		"e_ext_san_edi_party_name_present",
		"e_ext_san_empty_name",
		"e_ext_san_missing",
		"e_ext_san_no_entries",
		"e_ext_san_not_critical_without_subject",
		"e_ext_san_other_name_present",
		"e_ext_san_registered_id_present",
		"e_ext_san_rfc822_format_invalid",
		"e_ext_san_rfc822_name_present",
		"e_ext_san_space_dns_name",
		"e_ext_san_uniform_resource_identifier_present",
		"e_ext_san_uri_format_invalid",
		"e_ext_san_uri_host_not_fqdn_or_ip",
		"e_ext_san_uri_not_ia5",
		"e_ext_san_uri_relative",
		"e_ext_subject_directory_attr_critical",
		"e_ext_subject_key_identifier_critical",
		"e_ext_subject_key_identifier_missing_ca",
		"e_generalized_time_does_not_include_seconds",
		"e_generalized_time_includes_fraction_seconds",
		"e_generalized_time_not_in_zulu",
		"e_ian_bare_wildcard",
		"e_ian_dns_name_includes_null_char",
		"e_ian_dns_name_starts_with_period",
		"e_ian_wildcard_not_first",
		"e_inhibit_any_policy_not_critical",
		"e_international_dns_name_not_nfc",
		"e_international_dns_name_not_unicode",
		"e_invalid_certificate_version",
		"e_issuer_dn_country_not_printable_string",
		"e_issuer_field_empty",
		"e_name_constraint_empty",
		"e_name_constraint_maximum_not_absent",
		"e_name_constraint_minimum_non_zero",
		"e_old_root_ca_rsa_mod_less_than_2048_bits",
		"e_old_sub_ca_rsa_mod_less_than_1024_bits",
		"e_old_sub_cert_rsa_mod_less_than_1024_bits",
		"e_path_len_constraint_improperly_included",
		"e_path_len_constraint_zero_or_less",
		"e_public_key_type_not_allowed",
		"e_qcstatem_etsi_present_qcs_critical",
		"e_qcstatem_etsi_type_as_statem",
		"e_qcstatem_mandatory_etsi_statems",
		"e_qcstatem_qccompliance_valid",
		"e_qcstatem_qclimitvalue_valid",
		"e_qcstatem_qcpds_valid",
		"e_qcstatem_qcretentionperiod_valid",
		"e_qcstatem_qcsscd_valid",
		"e_qcstatem_qctype_valid",
		"e_root_ca_extended_key_usage_present",
		"e_root_ca_key_usage_must_be_critical",
		"e_root_ca_key_usage_present",
		"e_rsa_exp_negative",
		"e_rsa_mod_less_than_2048_bits",
		"e_rsa_no_public_key",
		"e_rsa_public_exponent_not_odd",
		"e_rsa_public_exponent_too_small",
		"e_san_bare_wildcard",
		"e_san_dns_name_includes_null_char",
		"e_san_dns_name_starts_with_period",
		"e_san_wildcard_not_first",
		"e_serial_number_longer_than_20_octets",
		"e_serial_number_not_positive",
		"e_signature_algorithm_not_supported",
		"e_sub_ca_aia_does_not_contain_ocsp_url",
		"e_sub_ca_aia_marked_critical",
		"e_sub_ca_aia_missing",
		"e_sub_ca_certificate_policies_missing",
		"e_sub_ca_crl_distribution_points_does_not_contain_url",
		"e_sub_ca_crl_distribution_points_marked_critical",
		"e_sub_ca_crl_distribution_points_missing",
		"e_sub_cert_aia_does_not_contain_ocsp_url",
		"e_sub_cert_aia_marked_critical",
		"e_sub_cert_aia_missing",
		"e_sub_cert_cert_policy_empty",
		"e_sub_cert_certificate_policies_missing",
		"e_sub_cert_country_name_must_appear",
		"e_sub_cert_crl_distribution_points_does_not_contain_url",
		"e_sub_cert_crl_distribution_points_marked_critical",
		"e_sub_cert_eku_missing",
		"e_sub_cert_eku_server_auth_client_auth_missing",
		"e_sub_cert_given_name_surname_contains_correct_policy",
		"e_sub_cert_key_usage_cert_sign_bit_set",
		"e_sub_cert_key_usage_crl_sign_bit_set",
		"e_sub_cert_locality_name_must_appear",
		"e_sub_cert_locality_name_must_not_appear",
		"e_sub_cert_not_is_ca",
		"e_sub_cert_or_sub_ca_using_sha1",
		"e_sub_cert_postal_code_must_not_appear",
		"e_sub_cert_province_must_appear",
		"e_sub_cert_province_must_not_appear",
		"e_sub_cert_street_address_should_not_exist",
		"e_sub_cert_valid_time_longer_than_39_months",
		"e_sub_cert_valid_time_longer_than_825_days",
		"e_subject_common_name_max_length",
		"e_subject_common_name_not_from_san",
		"e_subject_contains_noninformational_value",
		"e_subject_contains_reserved_ip",
		"e_subject_country_not_iso",
		"e_subject_dn_country_not_printable_string",
		"e_subject_dn_not_printable_characters",
		"e_subject_dn_serial_number_max_length",
		"e_subject_dn_serial_number_not_printable_string",
		"e_subject_email_max_length",
		"e_subject_empty_without_san",
		"e_subject_given_name_max_length",
		"e_subject_info_access_marked_critical",
		"e_subject_locality_name_max_length",
		"e_subject_not_dn",
		"e_subject_organization_name_max_length",
		"e_subject_organizational_unit_name_max_length",
		"e_subject_postal_code_max_length",
		"e_subject_state_name_max_length",
		"e_subject_street_address_max_length",
		"e_subject_surname_max_length",
		"e_utc_time_does_not_include_seconds",
		"e_utc_time_not_in_zulu",
		"e_validity_time_not_positive",
		"e_wrong_time_format_pre2050",
		"n_ca_digital_signature_not_set",
		"n_contains_redacted_dnsname",
		"n_multiple_subject_rdn",
		"n_san_dns_name_duplicate",
		"n_sub_ca_eku_missing",
		"n_sub_ca_eku_not_technically_constrained",
		"n_subject_common_name_included",
		"onion_subject_validity_time_too_large",
		"san_dns_name_onion_not_ev_cert",
		"subject_contains_malformed_arpa_ip",
		"subject_contains_reserved_arpa_ip",
		"w_distribution_point_missing_ldap_or_uri",
		"w_eku_critical_improperly",
		"w_ext_aia_access_location_missing",
		"w_ext_cert_policy_contains_noticeref",
		"w_ext_cert_policy_explicit_text_includes_control",
		"w_ext_cert_policy_explicit_text_not_nfc",
		"w_ext_cert_policy_explicit_text_not_utf8",
		"w_ext_crl_distribution_marked_critical",
		"w_ext_ian_critical",
		"w_ext_key_usage_not_critical",
		"w_ext_policy_map_not_critical",
		"w_ext_policy_map_not_in_cert_policy",
		"w_ext_san_critical_with_subject_dn",
		"w_ext_subject_key_identifier_missing_sub_cert",
		"w_ian_iana_pub_suffix_empty",
		"w_issuer_dn_leading_whitespace",
		"w_issuer_dn_trailing_whitespace",
		"w_multiple_issuer_rdn",
		"w_name_constraint_on_edi_party_name",
		"w_name_constraint_on_registered_id",
		"w_name_constraint_on_x400",
		"w_qcstatem_qcpds_lang_case",
		"w_qcstatem_qctype_web",
		"w_root_ca_basic_constraints_path_len_constraint_field_present",
		"w_root_ca_contains_cert_policy",
		"w_rsa_mod_factors_smaller_than_752",
		"w_rsa_mod_not_odd",
		"w_rsa_public_exponent_not_in_range",
		"w_serial_number_low_entropy",
		"w_sub_ca_aia_does_not_contain_issuing_ca_url",
		"w_sub_ca_certificate_policies_marked_critical",
		"w_sub_ca_eku_critical",
		"w_sub_ca_name_constraints_not_critical",
		"w_sub_cert_aia_does_not_contain_issuing_ca_url",
		"w_sub_cert_certificate_policies_marked_critical",
		"w_sub_cert_eku_extra_values",
		"w_sub_cert_sha1_expiration_too_long",
		"w_subject_dn_leading_whitespace",
		"w_subject_dn_trailing_whitespace",
	}

	results := make([]string, len(lints))

	for i, lint := range lints {
		results[i] = set.Results[lint].Status.String()
	}

	return results
}

func certParser(rawCertRecords chan []string, outputCertStrings chan string, outputZlintStrings chan string, wg *sync.WaitGroup) {
	parser := x509.NewCertParser()

	for record := range rawCertRecords {
		logTimestamps := make([]LogTimestamp, 0)
		var minLogTimestamp string

		encodedCertChain := strings.Split(strings.TrimSpace(record[*field-1]), *certChainDelimiter)

		if *appendChainField > 0 {
			if len(record[*appendChainField-1]) > 0 {
				rawChain := strings.Split(strings.TrimSpace(record[*appendChainField-1]), *certChainDelimiter)
				chainStartIndex := 0
				if rawChain[0] == encodedCertChain[0] {
					chainStartIndex = 1
				}
				encodedCertChain = append(encodedCertChain, rawChain[chainStartIndex:]...)
			}
		}

		if *logTimestampsField > 0 {
			logTimestampStrings := strings.Split(strings.TrimSpace(record[*logTimestampsField-1]), *certChainDelimiter)
			for _, str := range logTimestampStrings {
				splitLogTimestamp := strings.Split(str, ":")
				ts, err := strconv.Atoi(splitLogTimestamp[len(splitLogTimestamp)-1])
				if err != nil {
					log.Error(err)
				}
				logTimestamps = append(logTimestamps, LogTimestamp{
					Log:       strings.Join(splitLogTimestamp[:len(splitLogTimestamp)-1], ":"),
					Timestamp: ts,
				})
			}
		}

		var matchedDomains string
		if *certDomainMatchField > 0 {
			matchedDomains = record[*certDomainMatchField-1]
		}

		if *minLogTimestampField > 0 {
			minLogTimestamp = strings.TrimSpace(record[*minLogTimestampField-1])
		} else {
			minLogTimestamp = ""
		}

		certChain, err := decodeAndParseChain(encodedCertChain, parser)
		zlintResult := &zlint.ResultSet{}
		if len(certChain) > 0 && *runZlint {
			leafCert := certChain[0]
			zlintResult = zlint.LintCertificate(leafCert)
		}
		if err != nil {
			continue
		} else {
			switch *outputFormat {
			case "json":
				var zlintJson *zlint.ResultSet
				if *zlintOutDir == "" {
					zlintJson = zlintResult
				}

				processedChain, err := extractFeaturesToJSON(certChain, zlintJson, logTimestamps, minLogTimestamp, matchedDomains)
				if err != nil {
					log.Fatal(err)
				}

				jsonBytes, err := json.Marshal(processedChain)
				if err != nil {
					log.Fatal(err)
				} else {
					outputCertStrings <- string(jsonBytes) + "\n"
				}

				if len(certChain) > 0 && *runZlint && *zlintOutDir != "" {
					zlintOutput := make([]string, 0)
					leafCert := processedChain.Leaf
					zlintOutput = append(zlintOutput, leafCert.FingerprintSHA256.Hex())
					jsonEncodedFP, err := json.Marshal(processedChain.LeafAsn1FingerprintSubj)
					if err != nil {
						log.Fatal(err)
					}
					zlintOutput = append(zlintOutput, string(jsonEncodedFP))
					zlintOutput = append(zlintOutput, leafCert.Issuer.String())
					zlintOutput = append(zlintOutput, ZlintToString(zlintResult)...)
					outputZlintStrings <- strings.Join(zlintOutput, "|") + "\n"
				}

			case "csv":
				log.Fatal("CSV not implemented yet...")
			default:
				log.Fatal("Must specify either json or csv format")
			}
		}
	}

	wg.Done()
}

func readCertificates(filepaths []string, rawCertRecord chan []string, wg *sync.WaitGroup) {
	for _, filepath := range filepaths {
		log.Infof("reading file %s", filepath)
		f, err := os.Open(filepath)
		if err != nil {
			log.Error(err)
			continue
		}

		reader := csv.NewReader(f)
		reader.Comma = rune((*delimiter)[0])

		records, err := reader.ReadAll()
		for _, line := range records {
			rawCertRecord <- line
		}
		f.Close()
	}
	wg.Done()
}

func main() {
	certificate_scanner.log.Debug('')
	//
	//flag.Parse()
	//
	//if *cpuProfile {
	//	defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	//}
	//if *memProfile {
	//	defer profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	//}
	//
	//if *fname == "" {
	//	log.Fatal("Must provide a certificate file to parse!")
	//}
	//
	//log.Info("Loading root stores")
	//for _, rootStore := range rootStores {
	//	rootStore.Load()
	//}
	//
	//log.Info("Starting cert feature extraction")
	//
	//if ok, err := exists(*fname); err != nil || !ok {
	//	log.Fatal("Invalid input file/directory: ", *fname)
	//}
	//
	//var filepaths []string
	//
	//if isDir, err := isDirectory(*fname); err != nil {
	//	log.Fatal("Unable to determine if input path is file/directory: ", *fname)
	//} else if isDir {
	//	filepaths, err = mwdomains.GetCertFiles(*fname, *suffix, *recursiveDir)
	//	if err != nil {
	//		log.Fatal("Unable to retrieve files from diretory: ", err)
	//	}
	//} else if !isDir {
	//	filepaths = []string{*fname}
	//}
	//
	//rawCertRecords := make(chan []string, *workerCount)
	//readWG := &sync.WaitGroup{}
	//readWG.Add(1)
	//go readCertificates(filepaths, rawCertRecords, readWG)
	//
	//parsedCertStrings := make(chan string)
	//parsedZlintStrings := make(chan string)
	//
	//workerWG := &sync.WaitGroup{}
	//for i := 0; i < *workerCount; i++ {
	//	workerWG.Add(1)
	//	go certParser(rawCertRecords, parsedCertStrings, parsedZlintStrings, workerWG)
	//}
	//
	//writeWG := &sync.WaitGroup{}
	//writeWG.Add(1)
	//go writeCertificates(parsedCertStrings, writeWG)
	//
	//writeZlintWG := &sync.WaitGroup{}
	//writeZlintWG.Add(1)
	//go writeZlint(parsedZlintStrings, writeZlintWG)
	//
	//readWG.Wait()
	//close(rawCertRecords)
	//workerWG.Wait()
	//close(parsedCertStrings)
	//close(parsedZlintStrings)
	//writeWG.Wait()
	//writeZlintWG.Wait()
}
