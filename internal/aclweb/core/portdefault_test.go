package core

import "testing"

// TestEqWithNoPortMeansNoPortCondition guards the consequence of making "eq" the
// form's default: the operator now arrives on every submission, including the
// ones where the port field was left alone. An empty number field parses to 0,
// so without this the rule would have gone out matching port 0.
func TestEqWithNoPortMeansNoPortCondition(t *testing.T) {
	r := SubmitRequest{Protocol: "TCP", DstIP: "10.0.0.1", DstPortOp: "eq"}
	r.normalize()
	if r.DstPortOp != "" {
		t.Errorf("dst_port_op = %q, want it dropped when no port was given", r.DstPortOp)
	}
	r = SubmitRequest{Protocol: "tcp", DstIP: "10.0.0.1", DstPortOp: "eq", DstPortVal: 80}
	r.normalize()
	if r.DstPortOp != "eq" || r.DstPortVal != 80 {
		t.Errorf("dst_port = %q/%d, want eq/80 kept", r.DstPortOp, r.DstPortVal)
	}
	r = SubmitRequest{Protocol: "tcp", DstIP: "10.0.0.1", DstPortVal: 80}
	r.normalize()
	if r.DstPortVal != 0 {
		t.Errorf("dst_port_val = %d, want a port with no operator dropped", r.DstPortVal)
	}
}
