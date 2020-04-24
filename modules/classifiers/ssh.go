package classifiers

import (
	"github.com/N0mansky/go-dpi/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
)

// SSHClassifier struct
type SSHClassifier struct{}

// HeuristicClassify for SSHClassifier
func (classifier SSHClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, _ []gopacket.Packet) bool {
			payloadStr := string(payload)
			hasSuffix := strings.HasSuffix(payloadStr, "\n")
			hasSSHStr := strings.HasPrefix(payloadStr, "SSH") || strings.Contains(payloadStr, "OpenSSH")
			return hasSuffix && hasSSHStr
		})
}

// GetProtocol returns the corresponding protocol
func (classifier SSHClassifier) GetProtocol() types.Protocol {
	return types.SSH
}
