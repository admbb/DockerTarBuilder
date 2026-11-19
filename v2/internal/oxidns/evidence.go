package oxidns

import (
	"fmt"
	"netflow-plus-v2/internal/correlation"
	"strings"
	"time"
)

// Evidence preserves the source event identity and decoded response metadata;
// query counts are independent from byte counts.
func (r Record) Evidence() (correlation.DNSEvent, error) {
	if r.ID <= 0 || r.CreatedAtMS <= 0 || r.ClientIP == "" {
		return correlation.DNSEvent{}, fmt.Errorf("invalid recorder event")
	}
	status := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.RCode), " ", ""))
	out := correlation.DNSEvent{ID: r.ID, ClientIP: r.ClientIP, At: time.UnixMilli(r.CreatedAtMS), ResponseOK: r.HasResponse && (status == "noerror" || status == "0")}
	for _, q := range r.Questions {
		out.Questions = append(out.Questions, correlation.Question{Name: q.Name, Type: q.QType})
	}
	for _, a := range r.Answers {
		out.Answers = append(out.Answers, correlation.Answer{Name: a.Name, Type: a.Type, Data: a.Data, TTL: a.TTL})
	}
	return out, nil
}
