package risk

// ImpactInputs is the per-host context used to compute I_host from signals
// observable without asset classification: blast radius (service / management
// port footprint or graph) and lateral-movement potential.
type ImpactInputs struct {
	ServiceCount  int32
	MgmtPortCount int32
	GraphLateral  float64
	GraphBlast    float64
}

// ImpactComponent is one explainable contributor to I_host so the UI can
// render "blast radius contributes 0.15, lateral potential 0.10…"
type ImpactComponent struct {
	Code         string
	Label        string
	Weight       float64
	Contribution float64
}

// ImpactResult is the per-host impact score + breakdown.
type ImpactResult struct {
	I          float64
	Components []ImpactComponent
}

// ComputeHostImpact returns I_host ∈ [0,1] and the explanation. Impact is the
// untagged baseline plus the observable blast-radius and lateral-potential
// signals.
func ComputeHostImpact(inputs ImpactInputs, policy Policy) ImpactResult {
	blast := clamp01(inputs.GraphBlast)
	if blast == 0 {
		blast = clamp01(blastFromCounts(inputs.ServiceCount, inputs.MgmtPortCount))
	}

	lateral := clamp01(inputs.GraphLateral)

	components := []ImpactComponent{
		{
			Code:         "blast",
			Label:        "Blast radius",
			Weight:       policy.WeightBlast,
			Contribution: policy.WeightBlast * blast,
		},
		{
			Code:         "lateral",
			Label:        "Lateral potential",
			Weight:       policy.WeightLateral,
			Contribution: policy.WeightLateral * lateral,
		},
	}

	impact := policy.UntaggedImpactBaseline
	for _, component := range components {
		impact += component.Contribution
	}

	return ImpactResult{
		I:          clamp01(impact),
		Components: components,
	}
}

func blastFromCounts(services, mgmt int32) float64 {
	if services <= 0 {
		return 0
	}

	servicesPart := float64(services) / 20.0
	if servicesPart > 0.7 {
		servicesPart = 0.7
	}

	mgmtPart := float64(mgmt) / 5.0
	if mgmtPart > 0.3 {
		mgmtPart = 0.3
	}

	return servicesPart + mgmtPart
}
