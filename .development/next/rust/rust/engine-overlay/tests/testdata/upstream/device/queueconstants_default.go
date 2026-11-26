package device

import "github.com/amnezia-vpn/amneziawg-go/v3/conn"

const (
	QueueStagedSize            = conn.IdealBatchSize
	QueueOutboundSize          = 1024
	QueueInboundSize           = 1024
	QueueHandshakeSize         = 1024
	MaxSegmentSize             = (1 << 16) - 1
	PreallocatedBuffersPerPool = 0
)
