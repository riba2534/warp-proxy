package health

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationMilliseconds(t *testing.T) {
	b, _ := json.Marshal(Result{CheckDuration: 200 * time.Millisecond})
	var d map[string]interface{}
	json.Unmarshal(b, &d)
	if d["check_duration_ms"] != float64(200) {
		t.Fatalf("200ms encoded as %v in check_duration_ms", d["check_duration_ms"])
	}
}
