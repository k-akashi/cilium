// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NodeElement Known node in the cluster
//
// +k8s:deepcopy-gen=true
//
// swagger:model NodeElement
type NodeElement struct {

	// Address used for probing cluster connectivity
	HealthEndpointAddress *NodeAddressing `json:"health-endpoint-address,omitempty"`

	// Source address for Ingress listener
	IngressAddress *NodeAddressing `json:"ingress-address,omitempty"`

	// Name of the node including the cluster association. This is typically
	// <clustername>/<hostname>.
	//
	Name string `json:"name,omitempty"`

	// Primary address used for intra-cluster communication
	PrimaryAddress *NodeAddressing `json:"primary-address,omitempty"`

	// Alternative addresses assigned to the node
	SecondaryAddresses []*NodeAddressingElement `json:"secondary-addresses"`

	// Source of the node configuration
	Source string `json:"source,omitempty"`
}

// Validate validates this node element
func (m *NodeElement) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHealthEndpointAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIngressAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrimaryAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSecondaryAddresses(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NodeElement) validateHealthEndpointAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.HealthEndpointAddress) { // not required
		return nil
	}

	if m.HealthEndpointAddress != nil {
		if err := m.HealthEndpointAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("health-endpoint-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("health-endpoint-address")
			}
			return err
		}
	}

	return nil
}

func (m *NodeElement) validateIngressAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.IngressAddress) { // not required
		return nil
	}

	if m.IngressAddress != nil {
		if err := m.IngressAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ingress-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ingress-address")
			}
			return err
		}
	}

	return nil
}

func (m *NodeElement) validatePrimaryAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.PrimaryAddress) { // not required
		return nil
	}

	if m.PrimaryAddress != nil {
		if err := m.PrimaryAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("primary-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("primary-address")
			}
			return err
		}
	}

	return nil
}

func (m *NodeElement) validateSecondaryAddresses(formats strfmt.Registry) error {
	if swag.IsZero(m.SecondaryAddresses) { // not required
		return nil
	}

	for i := 0; i < len(m.SecondaryAddresses); i++ {
		if swag.IsZero(m.SecondaryAddresses[i]) { // not required
			continue
		}

		if m.SecondaryAddresses[i] != nil {
			if err := m.SecondaryAddresses[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("secondary-addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("secondary-addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this node element based on the context it is used
func (m *NodeElement) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateHealthEndpointAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIngressAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePrimaryAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSecondaryAddresses(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NodeElement) contextValidateHealthEndpointAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.HealthEndpointAddress != nil {

		if swag.IsZero(m.HealthEndpointAddress) { // not required
			return nil
		}

		if err := m.HealthEndpointAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("health-endpoint-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("health-endpoint-address")
			}
			return err
		}
	}

	return nil
}

func (m *NodeElement) contextValidateIngressAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.IngressAddress != nil {

		if swag.IsZero(m.IngressAddress) { // not required
			return nil
		}

		if err := m.IngressAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ingress-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ingress-address")
			}
			return err
		}
	}

	return nil
}

func (m *NodeElement) contextValidatePrimaryAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.PrimaryAddress != nil {

		if swag.IsZero(m.PrimaryAddress) { // not required
			return nil
		}

		if err := m.PrimaryAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("primary-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("primary-address")
			}
			return err
		}
	}

	return nil
}

func (m *NodeElement) contextValidateSecondaryAddresses(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SecondaryAddresses); i++ {

		if m.SecondaryAddresses[i] != nil {

			if swag.IsZero(m.SecondaryAddresses[i]) { // not required
				return nil
			}

			if err := m.SecondaryAddresses[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("secondary-addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("secondary-addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *NodeElement) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NodeElement) UnmarshalBinary(b []byte) error {
	var res NodeElement
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
