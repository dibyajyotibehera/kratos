package webauthn

import (
	_ "embed"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"strings"
)

//go:embed js/register.js
var jsRegister []byte

//go:embed js/login.js
var jsLogin []byte

func NewWebAuthnConnection(options string) *node.Node {
	return node.NewInputField(node.WebAuthnRegister, "", node.WebAuthnGroup,
		node.InputAttributeTypeSubmit, node.WithInputAttributes(func(a *node.InputAttributes) {
			a.OnClick = strings.Replace(string(jsRegister), "injectWebAuthnOptions", options, 1)
		})).
		WithMetaLabel(text.NewInfoSelfServiceRegisterWebAuthn())
}

func NewWebAuthnLogin(options string) *node.Node {
	return node.NewInputField(node.WebAuthnLogin, "", node.WebAuthnGroup,
		node.InputAttributeTypeSubmit, node.WithInputAttributes(func(a *node.InputAttributes) {
			a.OnClick = strings.Replace(string(jsLogin), "injectWebAuthnOptions", options, 1)
		})).
		WithMetaLabel(text.NewInfoSelfServiceLoginWebAuthn())
}

func NewWebAuthnConnectionName() *node.Node {
	return node.NewInputField(node.WebAuthnRegisterDisplayName, "", node.WebAuthnGroup, node.InputAttributeTypeText).
		WithMetaLabel(text.NewInfoSelfServiceRegisterWebAuthnDisplayName())
}

func NewWebAuthnUnlink(c *Credential) *node.Node {
	return node.NewInputField(node.WebAuthnRemove, c.ID, node.WebAuthnGroup,
		node.InputAttributeTypeSubmit).
		WithMetaLabel(text.NewInfoSelfServiceRemoveWebAuthn(c.DisplayName, c.AddedAt))
}
