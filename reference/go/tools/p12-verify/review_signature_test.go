package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestReviewDecodersRejectUnknownAndTrailingJSON(t *testing.T) {
	for name, decode := range map[string]func([]byte) error{
		"human review":   func(data []byte) error { _, err := decodeHumanReview(bytes.NewReader(data)); return err },
		"reviewer trust": func(data []byte) error { _, err := decodeReviewerTrust(bytes.NewReader(data)); return err },
	} {
		t.Run(name+" unknown", func(t *testing.T) {
			if err := decode([]byte(`{"schema_version":1,"unexpected":true}`)); err == nil {
				t.Fatal("unknown field accepted")
			}
		})
		t.Run(name+" trailing", func(t *testing.T) {
			if err := decode([]byte(`{} {}`)); err == nil {
				t.Fatal("trailing JSON accepted")
			}
		})
	}
}

func TestCheckedInApprovalFilesAreTruthfullyPending(t *testing.T) {
	reviewFile, err := os.Open("../../docs/p12/human-review.json")
	if err != nil {
		t.Fatal(err)
	}
	defer reviewFile.Close()
	review, err := decodeHumanReview(reviewFile)
	if err != nil {
		t.Fatal(err)
	}
	if review.Status != "pending" || review.ReviewedCandidate != nil || len(review.Reviews) != 0 {
		t.Fatalf("pending review contains approval evidence: %#v", review)
	}
	trustFile, err := os.Open("../../docs/p12/reviewer-trust.json")
	if err != nil {
		t.Fatal(err)
	}
	defer trustFile.Close()
	trust, err := decodeReviewerTrust(trustFile)
	if err != nil {
		t.Fatal(err)
	}
	if trust.Status != "pending" || len(trust.Keys) != 0 {
		t.Fatalf("pending trust policy contains identities or keys: %#v", trust)
	}
}

func TestSignedHumanReviewValidation(t *testing.T) {
	review, trust, candidate, reportData := generatedSignedReview(t)
	if err := validateHumanReview(review, trust, candidate, reportData); err != nil {
		t.Fatalf("valid generated approvals rejected: %v", err)
	}

	tests := map[string]func(*humanReviewReport, *reviewerTrustPolicy, *[]byte){
		"fabricated URI without signature": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.Reviews[0].ApprovalReference = "https://approvals.example.test/fabricated"
			review.Reviews[0].Signature = ""
		},
		"wrong key role": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.Reviews[0].KeyID = review.Reviews[1].KeyID
		},
		"tampered payload": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.Reviews[0].UnresolvedFindings.Medium++
		},
		"duplicate role": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.Reviews[1].Role = review.Reviews[0].Role
		},
		"candidate hash mismatch": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.ReviewedCandidate.Report.SHA256 = strings.Repeat("0", 64)
		},
		"approval predates completion": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.Reviews[0].StartedAt = candidate.FinishedAt
		},
		"pending blocks certification": func(review *humanReviewReport, _ *reviewerTrustPolicy, _ *[]byte) {
			review.Status = "pending"
		},
		"pending trust blocks certification": func(_ *humanReviewReport, trust *reviewerTrustPolicy, _ *[]byte) {
			trust.Status = "pending"
			trust.Keys = nil
		},
		"candidate bytes changed": func(_ *humanReviewReport, _ *reviewerTrustPolicy, reportData *[]byte) {
			*reportData = append(*reportData, '\n')
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changedReview := cloneJSON(t, review)
			changedTrust := cloneJSON(t, trust)
			changedData := append([]byte(nil), reportData...)
			mutate(&changedReview, &changedTrust, &changedData)
			if err := validateHumanReview(changedReview, changedTrust, candidate, changedData); err == nil {
				t.Fatal("invalid detached approval was accepted")
			}
		})
	}
}

func TestCandidateRejectsEmbeddedReviewBinding(t *testing.T) {
	value := report{Status: "candidate", Reviews: &reviewBinding{Path: humanReviewPath, Status: "approved", SHA256: strings.Repeat("a", 64)}}
	if err := validateDetachedReviews(value, t.TempDir()); err == nil {
		t.Fatal("candidate with embedded review binding accepted")
	}
}

func TestTrustPolicyRejectsDuplicateKeyAndRole(t *testing.T) {
	_, trust, _, _ := generatedSignedReview(t)
	trust.Keys[1].KeyID = trust.Keys[0].KeyID
	if _, err := validateTrustPolicy(trust); err == nil {
		t.Fatal("duplicate key ID accepted")
	}
	_, trust, _, _ = generatedSignedReview(t)
	trust.Keys[1].Role = trust.Keys[0].Role
	if _, err := validateTrustPolicy(trust); err == nil {
		t.Fatal("duplicate role authorization accepted")
	}
}

func TestTrustPolicyRequiresIndependentKeysAndReviewers(t *testing.T) {
	_, trust, _, _ := generatedSignedReview(t)
	trust.Keys[1].PublicKey = trust.Keys[0].PublicKey
	if _, err := validateTrustPolicy(trust); err == nil {
		t.Fatal("one decoded public key authorized independent roles")
	}

	_, trust, _, _ = generatedSignedReview(t)
	trust.Keys[1].ReviewerIdentity = strings.ToUpper(trust.Keys[0].ReviewerIdentity)
	trust.Keys[1].ReviewerAffiliation = strings.ToUpper(trust.Keys[0].ReviewerAffiliation)
	if _, err := validateTrustPolicy(trust); err == nil {
		t.Fatal("one normalized reviewer authorized independent roles")
	}
}

func TestCanonicalPayloadIsDeterministicAndNewlineTerminated(t *testing.T) {
	review, _, _, _ := generatedSignedReview(t)
	first, err := canonicalPayload(review, review.Reviews[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalPayload(cloneJSON(t, review), cloneJSON(t, review.Reviews[0]))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || len(first) == 0 || first[len(first)-1] != '\n' || first[len(first)-2] == '\n' {
		t.Fatalf("canonical payload is unstable or incorrectly framed: %q", first)
	}
}

func generatedSignedReview(t *testing.T) (humanReviewReport, reviewerTrustPolicy, report, []byte) {
	t.Helper()
	version := "v1.2.3"
	candidate := report{Status: "candidate", FinishedAt: "2026-09-16T10:00:00Z", Reviews: nil}
	candidate.Qualification = &qualificationBinding{Path: "docs/p12/qualification-report.json", Status: "passed", SHA256: strings.Repeat("a", 64)}
	candidate.Fuzz = &fuzzBinding{Path: "docs/p12/fuzz-report.json", Status: "passed", Profile: "certifying", SHA256: strings.Repeat("b", 64)}
	candidate.Release = releaseEvidence{Version: &version, Artifacts: map[string]string{
		"SHA256SUMS": strings.Repeat("1", 64), "go-librados-v1.2.3.spdx.json": strings.Repeat("2", 64),
		"go-librados-v1.2.3.tar.gz": strings.Repeat("3", 64), "go-librados-v1.2.3.zip": strings.Repeat("4", 64),
	}}
	reportData, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(reportData)
	review := humanReviewReport{SchemaVersion: 2, Status: "approved", RequiredRoles: append([]string(nil), requiredReviewRoles...), ReviewedCandidate: &reviewedCandidate{
		Report: fileBinding{Path: candidateReportPath, SHA256: digest}, Qualification: *candidate.Qualification,
		Fuzz:    *candidate.Fuzz,
		Release: reviewedRelease{Version: version, Artifacts: candidate.Release.Artifacts},
	}}
	trust := reviewerTrustPolicy{SchemaVersion: 1, Status: "active"}
	for index, role := range requiredReviewRoles {
		seed := make([]byte, ed25519.SeedSize)
		for offset := range seed {
			seed[offset] = byte(index + offset + 1)
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		keyID := "test-" + strings.ReplaceAll(role, "/", "-")
		identity := "Test Reviewer " + role
		affiliation := "Test Organization"
		trust.Keys = append(trust.Keys, trustedKey{KeyID: keyID, Role: role, ReviewerIdentity: identity, ReviewerAffiliation: affiliation, PublicKey: base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))})
		record := humanReviewRecord{Role: role, KeyID: keyID, ReviewerIdentity: identity, ReviewerAffiliation: affiliation, StartedAt: "2026-09-16T10:00:01Z", CompletedAt: "2026-09-16T10:01:00Z", Decision: "approved", ApprovalReference: "https://approvals.example.test/p12/" + keyID}
		review.Reviews = append(review.Reviews, record)
		payload, err := canonicalPayload(review, review.Reviews[index])
		if err != nil {
			t.Fatal(err)
		}
		review.Reviews[index].Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	}
	return review, trust, candidate, reportData
}

func cloneJSON[T any](t *testing.T, value T) T {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
