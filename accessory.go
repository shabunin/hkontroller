package hkontroller

type Accessory struct {
	Id uint64                `json:"aid"`
	Ss []*ServiceDescription `json:"services"`
}

type Accessories struct {
	Accs []*Accessory `json:"accessories,omitempty"`
}

func (a *Accessory) GetService(serviceType HapServiceType) *ServiceDescription {

	for _, s := range a.Ss {
		if s.Type.ToShort() == serviceType.ToShort() {
			return s
		}
	}

	return nil
}

// clone returns deep copy of accessory, so it can be read
// while values of device accessories are updated by events.
func (a *Accessory) clone() *Accessory {
	res := *a
	res.Ss = make([]*ServiceDescription, len(a.Ss))
	for i, s := range a.Ss {
		res.Ss[i] = s.clone()
	}
	return &res
}
