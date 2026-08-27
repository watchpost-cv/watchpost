package domain

type PostID string
type CollectorID string
type SignalName string

type PostKind string

const (
	PostKindHost                PostKind = "host"
	PostKindHTTPEndpoint        PostKind = "http_endpoint"
	PostKindTCPService          PostKind = "tcp_service"
	PostKindTLSCert             PostKind = "tls_certificate"
	PostKindNetworkDevice       PostKind = "network_device"
	PostKindUPS                 PostKind = "ups"
	PostKindEnvironmentalSensor PostKind = "environmental_sensor"
	PostKindStorage             PostKind = "storage_appliance"
)

type Quality string

const (
	QualityGood      Quality = "good"
	QualityUncertain Quality = "uncertain"
	QualityBad       Quality = "bad"
	QualityMissing   Quality = "missing"
	QualityStale     Quality = "stale"
)
