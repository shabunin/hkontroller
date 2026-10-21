package hkontroller

type ServiceDescription struct {
	Id      uint64                       `json:"iid"`
	Type    HapServiceType               `json:"type"`
	Cs      []*CharacteristicDescription `json:"characteristics"`
	Hidden  *bool                        `json:"hidden,omitempty"`
	Primary *bool                        `json:"primary,omitempty"`
	Linked  []uint64                     `json:"linked,omitempty"`
}

func (s *ServiceDescription) GetCharacteristic(characteristicType HapCharacteristicType) *CharacteristicDescription {

	for _, c := range s.Cs {
		if c.Type.ToShort() == characteristicType.ToShort() {
			return c
		}
	}

	return nil
}

func (s *ServiceDescription) clone() *ServiceDescription {
	res := *s
	res.Linked = append([]uint64(nil), s.Linked...)
	res.Cs = make([]*CharacteristicDescription, len(s.Cs))
	for i, c := range s.Cs {
		cc := *c
		cc.Permissions = append([]string(nil), c.Permissions...)
		cc.ValidValues = append([]int(nil), c.ValidValues...)
		cc.ValidRange = append([]int(nil), c.ValidRange...)
		res.Cs[i] = &cc
	}
	return &res
}
