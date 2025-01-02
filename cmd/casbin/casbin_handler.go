package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"log/slog"
	"manaty226/authzen-interop-pdp-casbin/pip"
	"manaty226/authzen-interop-pdp-casbin/server"

	"github.com/casbin/casbin/v2"
)

type casbinHandler struct {
	enforcer *casbin.Enforcer
}

func NewCasbinHandler() server.Handler {
	e, err := casbin.NewEnforcer("./cmd/casbin/model.conf", "./cmd/casbin/policy.csv")
	if err != nil {
		log.Fatalln(err)
	}

	return &casbinHandler{
		enforcer: e,
	}
}

// this is used for casbin ABAC object policy
type object struct {
	ID      string
	OwnerID string
}

func (h casbinHandler) EvaluateAccess(ctx context.Context, req *server.EvaluateAccessReq) (*server.EvaluateAccessOK, error) {
	sub := pip.Users[req.Subject.ID]
	obj := object{
		ID:      fmt.Sprintf("%s::%s", req.Resource.Type, req.Resource.ID),
		OwnerID: req.Resource.Properties.Value.OwnerID.Value,
	}
	act := req.Action.Name

	ok, err := h.enforcer.Enforce(sub, obj, act)
	if err != nil {
		return nil, err
	}

	if !ok {
		slog.Info("EvaluateAccess", "decision", false, "sub", sub, "obj", obj, "action", act)
		return &server.EvaluateAccessOK{
			Decision: false,
		}, nil
	}

	slog.Info("EvaluateAccess", "decision", true, "sub", sub, "obj", obj, "action", act)
	return &server.EvaluateAccessOK{
		Decision: true,
	}, nil
}
