package devices

import (
	"context"
	"errors"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"time"

	"github.com/watchpost-cv/watchpost/internal/contract"
)

type OID struct{ Name, OID, Unit string }
type Profile struct {
	ID, Kind string
	OIDs     []OID
}
type Reading struct {
	Name, OID, Unit string
	Value           any
	Quality         string
	ObservedAt      time.Time
	FreshUntil      time.Time
}
type Getter interface {
	Get([]string) (*gosnmp.SnmpPacket, error)
}

func Poll(ctx context.Context, getter Getter, profile Profile) ([]Reading, error) {
	if len(profile.OIDs) < 1 || len(profile.OIDs) > 64 {
		return nil, errors.New("profile OID count out of bounds")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	ids := make([]string, len(profile.OIDs))
	byID := map[string]OID{}
	for i, item := range profile.OIDs {
		if item.Name == "" || item.OID == "" {
			return nil, errors.New("invalid OID profile")
		}
		ids[i] = item.OID
		byID[item.OID] = item
	}
	packet, err := getter.Get(ids)
	if err != nil {
		return nil, err
	}
	readings := []Reading{}
	for _, variable := range packet.Variables {
		item, ok := byID[variable.Name]
		if !ok {
			continue
		}
		quality := "good"
		if variable.Type == gosnmp.NoSuchObject || variable.Type == gosnmp.NoSuchInstance {
			quality = "missing"
		}
		now := time.Now().UTC()
		readings = append(readings, Reading{Name: item.Name, OID: item.OID, Unit: item.Unit, Value: variable.Value, Quality: quality, ObservedAt: now, FreshUntil: now.Add(5 * time.Minute)})
	}
	return readings, nil
}

// Observation converts a reading into the canonical observation envelope. Only
// numeric readings carry a value; non-numeric SNMP values become nil-value
// bad-quality observations rather than a fabricated number.
func (r Reading) Observation(method contract.Method, observedAt time.Time) contract.Observation {
	quality := contract.QualityBad
	if r.Quality == "good" {
		quality = contract.QualityGood
	}
	if r.Quality == "missing" {
		quality = contract.QualityMissing
	}
	return contract.Observation{
		Version: contract.ProtocolVersion, PostID: method.PostID,
		Source: contract.Source{Method: method, Identity: method.ID},
		Signal: r.Name, Value: floatValue(r.Value), Unit: r.Unit,
		Quality:    quality,
		ObservedAt: observedAt, IngestedAt: observedAt, FreshUntil: r.FreshUntil,
	}
}

// PollOK builds the reachability observation a recurring poll always emits, so
// a deterministic rule can fire when a device stops answering.
func PollOK(method contract.Method, ok bool, observedAt time.Time) contract.Observation {
	value := 0.0
	if ok {
		value = 1.0
	}
	return contract.Observation{
		Version: contract.ProtocolVersion, PostID: method.PostID,
		Source: contract.Source{Method: method, Identity: method.ID},
		Signal: "snmp.poll_ok", Value: &value, Unit: "boolean", Quality: contract.QualityGood,
		ObservedAt: observedAt, IngestedAt: observedAt, FreshUntil: observedAt.Add(5 * time.Minute),
	}
}

func floatValue(value any) *float64 {
	switch v := value.(type) {
	case int:
		f := float64(v)
		return &f
	case int8:
		f := float64(v)
		return &f
	case int16:
		f := float64(v)
		return &f
	case int32:
		f := float64(v)
		return &f
	case int64:
		f := float64(v)
		return &f
	case uint:
		f := float64(v)
		return &f
	case uint8:
		f := float64(v)
		return &f
	case uint16:
		f := float64(v)
		return &f
	case uint32:
		f := float64(v)
		return &f
	case uint64:
		f := float64(v)
		return &f
	case float32:
		f := float64(v)
		return &f
	case float64:
		return &v
	}
	return nil
}

type Preset struct {
	Kind, Name, Description string
	OIDs                    []OID
}

func Presets() []Preset {
	return []Preset{
		{Kind: "network_device", Name: "Network availability", Description: "Uptime and interface inventory", OIDs: []OID{{Name: "uptime", OID: ".1.3.6.1.2.1.1.3.0", Unit: "ticks"}, {Name: "interfaces", OID: ".1.3.6.1.2.1.2.1.0", Unit: "count"}}},
		{Kind: "ups", Name: "UPS or PDU", Description: "Battery charge, input voltage and load", OIDs: []OID{{Name: "battery_charge", OID: ".1.3.6.1.2.1.33.1.2.4.0", Unit: "percent"}, {Name: "input_voltage", OID: ".1.3.6.1.2.1.33.1.3.3.1.3.1", Unit: "volts"}, {Name: "output_load", OID: ".1.3.6.1.2.1.33.1.4.4.1.5.1", Unit: "percent"}}},
		{Kind: "environmental_sensor", Name: "Environment", Description: "Vendor-neutral placeholder for temperature and humidity OIDs", OIDs: []OID{}},
		{Kind: "storage_appliance", Name: "Storage appliance", Description: "Uptime plus vendor-specific capacity and health OIDs", OIDs: []OID{{Name: "uptime", OID: ".1.3.6.1.2.1.1.3.0", Unit: "ticks"}}},
	}
}

type V3Config struct {
	Address                                 string
	Port                                    uint16
	Username, AuthPassword, PrivacyPassword string
	Timeout                                 time.Duration
}

func NewV3(config V3Config) (*gosnmp.GoSNMP, error) {
	if config.Address == "" || config.Username == "" || config.AuthPassword == "" || config.PrivacyPassword == "" {
		return nil, errors.New("SNMPv3 authPriv credentials required")
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		return nil, errors.New("invalid SNMP timeout")
	}
	client := &gosnmp.GoSNMP{Target: config.Address, Port: config.Port, Version: gosnmp.Version3, Timeout: config.Timeout, Retries: 1, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: config.Username, AuthenticationProtocol: gosnmp.SHA256, PrivacyProtocol: gosnmp.AES, AuthenticationPassphrase: config.AuthPassword, PrivacyPassphrase: config.PrivacyPassword}}
	if client.Port == 0 {
		client.Port = 161
	}
	return client, nil
}
func ValidateProfile(profile Profile) error {
	allowed := map[string]bool{"network_device": true, "ups": true, "environmental_sensor": true, "storage_appliance": true}
	if profile.ID == "" || !allowed[profile.Kind] || len(profile.OIDs) > 64 {
		return fmt.Errorf("invalid device profile")
	}
	return nil
}
