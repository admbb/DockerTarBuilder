package oxidns

import (
	"netflow-plus-v2/internal/correlation"
	"testing"
	"time"
)

func TestEvidenceRealRCodeAndTTL(t *testing.T) {
	r := Record{ID: 1, CreatedAtMS: 1000, ClientIP: "192.168.1.2", HasResponse: true, RCode: "No Error", Questions: []Question{{Name: "www.example.com.", QType: "A"}}, Answers: []Answer{{Name: "www.example.com.", Type: "A", Data: "8.8.8.8", TTL: 30}}}
	evidence, err := r.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	result := correlation.Match(correlation.Flow{ClientIP: r.ClientIP, RemoteIP: "8.8.8.8", Start: time.UnixMilli(2000)}, []correlation.DNSEvent{evidence}, []correlation.Rule{{Domain: "example.com", AppID: "example"}}, 30*time.Second)
	if result.AppID != "example" {
		t.Fatalf("got %+v", result)
	}
	r.RCode = "Non-Existent Domain"
	evidence, err = r.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ResponseOK {
		t.Fatal("failed DNS marked successful")
	}
}
