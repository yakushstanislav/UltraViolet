package handler

import (
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"go.uber.org/zap"

	attackpathdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/attackpath"
	riskdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/risk"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/remediation"
	risksvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk"
)

func (h *Router) getAttackPathHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	view, err := h.services.Risk.GetAttackPath(ctx, addr)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, attackPathViewToDTO(view))
}

func attackPathViewToDTO(view risksvc.AttackPathView) attackpathdto.View {
	relations := make([]attackpathdto.Relation, 0, len(view.Relations))
	hosts := make([]attackpathdto.HostRef, 0, len(view.Hosts))

	for _, relation := range view.Relations {
		relations = append(relations, attackpathdto.Relation{
			SrcHostID:    relation.SrcHostID,
			DstHostID:    relation.DstHostID,
			RelationType: relation.RelationType,
			Strength:     relation.Strength,
			Evidence:     relation.EvidenceJSON,
		})
	}

	for hostID, ip := range view.Hosts {
		hosts = append(hosts, attackpathdto.HostRef{
			HostID: hostID,
			IP:     ip,
		})
	}

	slices.SortFunc(hosts, func(a, b attackpathdto.HostRef) int {
		switch {
		case a.HostID < b.HostID:
			return -1
		case a.HostID > b.HostID:
			return 1
		default:
			return 0
		}
	})

	response := attackpathdto.View{
		IP:        view.IP,
		Hosts:     hosts,
		Relations: relations,
		Score: attackpathdto.HostScore{
			HostID:                 view.Score.HostID,
			Centrality:             view.Score.Centrality,
			PivotScore:             view.Score.PivotScore,
			ReachableCriticalCount: view.Score.ReachableCriticalCount,
			TopPaths:               view.Score.TopPathsJSON,
		},
	}

	if !view.Score.ComputedAt.IsZero() {
		response.Score.ComputedAt = view.Score.ComputedAt.Format(time.RFC3339)
	}

	return response
}

func (h *Router) listHostRecommendationsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	limit := parseUintQuery(r, "limit", 20, 1, 200)

	view, err := h.services.Risk.ListRecommendations(ctx, addr, limit)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, riskdto.RecommendationsResponse{
		IP:              view.IP,
		Recommendations: remediationsToDTO(view.Recommendations),
	})
}

func remediationsToDTO(recs []remediation.Recommendation) []riskdto.Recommendation {
	out := make([]riskdto.Recommendation, 0, len(recs))

	for _, rec := range recs {
		out = append(out, riskdto.Recommendation{
			ID:                 rec.ID,
			HostID:             rec.HostID,
			ServiceID:          rec.ServiceID,
			ActionCode:         rec.ActionCode,
			Label:              rec.Label,
			ExpectedDeltaP:     rec.ExpectedDeltaP,
			ExpectedDeltaScore: rec.ExpectedDeltaScore,
			Evidence:           rec.Evidence,
			CreatedAt:          rec.CreatedAt.Format(time.RFC3339),
			UpdatedAt:          rec.UpdatedAt.Format(time.RFC3339),
		})
	}

	return out
}

func (h *Router) getRiskPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	policy, err := h.services.Risk.GetPolicy(ctx)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, policyToDTO(policy))
}

func (h *Router) updateRiskPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req riskdto.PolicyRequest

	if decodeErr := h.decodeBody(w, r, &req); decodeErr != nil {
		h.writeDecodeError(w, decodeErr)

		return
	}

	if validateErr := req.IsValid(); validateErr != nil {
		requestLogger.Warnw("Invalid risk policy request", zap.Error(validateErr))

		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	policy, err := h.services.Risk.UpdatePolicy(ctx, dtoToPolicy(req))
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, policyToDTO(policy))
}

func policyToDTO(policy risk.Policy) riskdto.PolicyResponse {
	return riskdto.PolicyResponse{
		KCoefficient:           policy.KCoefficient,
		WeightBlast:            policy.WeightBlast,
		WeightLateral:          policy.WeightLateral,
		KEVHalfLifeDays:        int(policy.KEVHalfLife / (24 * time.Hour)),
		EPSSHalfLifeDays:       int(policy.EPSSHalfLife / (24 * time.Hour)),
		RecencyHalfLifeDays:    int(policy.RecencyHalfLife / (24 * time.Hour)),
		TLSHalfLifeDays:        int(policy.TLSHalfLife / (24 * time.Hour)),
		KEVFloor:               policy.KEVFloor,
		EPSSFloor:              policy.EPSSFloor,
		RecencyFloor:           policy.RecencyFloor,
		TLSFloor:               policy.TLSFloor,
		UntaggedImpactBaseline: policy.UntaggedImpactBaseline,
		UntaggedConfidenceCap:  policy.UntaggedConfidenceCap,
		HighRiskThreshold:      policy.HighRiskThreshold,
	}
}

func dtoToPolicy(dto riskdto.PolicyRequest) risk.Policy {
	return risk.Policy{
		KCoefficient:           dto.KCoefficient,
		WeightBlast:            dto.WeightBlast,
		WeightLateral:          dto.WeightLateral,
		KEVHalfLife:            time.Duration(dto.KEVHalfLifeDays) * 24 * time.Hour,
		EPSSHalfLife:           time.Duration(dto.EPSSHalfLifeDays) * 24 * time.Hour,
		RecencyHalfLife:        time.Duration(dto.RecencyHalfLifeDays) * 24 * time.Hour,
		TLSHalfLife:            time.Duration(dto.TLSHalfLifeDays) * 24 * time.Hour,
		KEVFloor:               dto.KEVFloor,
		EPSSFloor:              dto.EPSSFloor,
		RecencyFloor:           dto.RecencyFloor,
		TLSFloor:               dto.TLSFloor,
		UntaggedImpactBaseline: dto.UntaggedImpactBaseline,
		UntaggedConfidenceCap:  dto.UntaggedConfidenceCap,
		HighRiskThreshold:      dto.HighRiskThreshold,
	}
}

func (h *Router) getServiceRiskExplainHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	view, err := h.services.Risk.ServiceRiskExplain(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	channels := make([]riskdto.ServiceExplainChannel, 0, len(view.Channels))

	for _, channel := range view.Channels {
		channels = append(channels, riskdto.ServiceExplainChannel{
			Code:    string(channel.Code),
			Label:   channel.Label,
			P:       channel.P,
			Sources: channel.Sources,
		})
	}

	h.sendJSONResponse(w, http.StatusOK, riskdto.ServiceExplainResponse{
		ServiceID:     view.ServiceID,
		HostID:        view.HostID,
		Port:          view.Port,
		Protocol:      view.Protocol,
		Probability:   view.Probability,
		RecencyFactor: view.RecencyFactor,
		Channels:      channels,
	})
}

func (h *Router) registerRiskAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin}
	admin := []auth.Role{auth.RoleAdmin}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/attack-paths/{ip}", read, h.getAttackPathHandler},
		{http.MethodGet, "/hosts/{ip}/risk-recommendations", read, h.listHostRecommendationsHandler},
		{http.MethodGet, "/services/{id}/risk-explain", read, h.getServiceRiskExplainHandler},
		{http.MethodGet, "/risk/policy", read, h.getRiskPolicyHandler},
		{http.MethodPatch, "/risk/policy", admin, h.updateRiskPolicyHandler},
	})
}
