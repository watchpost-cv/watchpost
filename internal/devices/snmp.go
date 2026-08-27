package devices

import (
	"context"
	"errors"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"time"
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
		readings = append(readings, Reading{Name: item.Name, OID: item.OID, Unit: item.Unit, Value: variable.Value, Quality: quality})
	}
	return readings, nil
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
