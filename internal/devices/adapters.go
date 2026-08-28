package devices

import "errors"

type AdapterDescriptor struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Authority    string   `json:"authority"`
	PostKinds    []string `json:"post_kinds"`
	Capabilities []string `json:"capabilities"`
}

func Adapters() []AdapterDescriptor {
	return []AdapterDescriptor{{ID: "snmpv3", Name: "SNMPv3 authPriv", Authority: "read_only", PostKinds: []string{"network_device", "ups", "environmental_sensor", "storage_appliance"}, Capabilities: []string{"poll_oids", "test_connection"}}}
}
func Adapter(id string) (AdapterDescriptor, error) {
	for _, v := range Adapters() {
		if v.ID == id {
			return v, nil
		}
	}
	return AdapterDescriptor{}, errors.New("device adapter not found")
}
