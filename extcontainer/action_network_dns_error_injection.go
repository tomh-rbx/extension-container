package extcontainer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-container/extcontainer/container/types"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkDNSErrorInjectionAction(r ociruntime.OciRuntime, client types.Client) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		ociRuntime:   r,
		client:       client,
		optsProvider: dnsErrorInjection(r),
		optsDecoder:  dnsErrorInjectionDecode,
		description:  getNetworkDNSErrorInjectionDescription(),
	}
}

func getNetworkDNSErrorInjectionDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_dns_error_injection", BaseActionID),
		Label:       "DNS Error Injection",
		Description: "Inject DNS errors (NXDOMAIN/SERVFAIL) into DNS queries using eBPF.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(delayIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  extutil.Ptr("Container"),
		Category:    extutil.Ptr("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: append(
			commonNetworkParameters,
			action_kit_api.ActionParameter{
				Name:         "dnsErrorTypes",
				Label:        "DNS Error Types",
				Description:  extutil.Ptr("Which DNS errors to inject?"),
				Type:         action_kit_api.ActionParameterTypeStringArray,
				DefaultValue: extutil.Ptr("[\"NXDOMAIN\"]"),
				Required:     extutil.Ptr(true),
				Options: extutil.Ptr([]action_kit_api.ParameterOption{
					action_kit_api.ExplicitParameterOption{
						Label: "NXDOMAIN",
						Value: "NXDOMAIN",
					},
					action_kit_api.ExplicitParameterOption{
						Label: "SERVFAIL",
						Value: "SERVFAIL",
					},
					action_kit_api.ExplicitParameterOption{
						Label: "Both (Random)",
						Value: "BOTH",
					},
				}),
				Order: extutil.Ptr(1),
			},
			action_kit_api.ActionParameter{
				Name:        "networkInterface",
				Label:       "Network Interface",
				Description: extutil.Ptr("Target Network Interface which should be affected. All if none specified."),
				Type:        action_kit_api.ActionParameterTypeStringArray,
				Required:    extutil.Ptr(false),
				Order:       extutil.Ptr(104),
			},
		),
	}
}

func dnsErrorInjection(r ociruntime.OciRuntime) networkOptsProvider {
	return func(ctx context.Context, sidecar network.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (network.Opts, action_kit_api.Messages, error) {
		errorTypes := extutil.ToStringArray(request.Config["dnsErrorTypes"])

		if len(errorTypes) == 0 {
			return nil, []action_kit_api.Message{{
				Level:   extutil.Ptr(action_kit_api.Error),
				Message: "Please select at least one DNS error type to inject.",
			}}, fmt.Errorf("no DNS error types configured")
		}

		// Validate error types
		validTypes := map[string]bool{
			"NXDOMAIN": true,
			"SERVFAIL": true,
			"BOTH":     true,
		}

		for _, errorType := range errorTypes {
			if !validTypes[errorType] {
				return nil, []action_kit_api.Message{{
					Level:   extutil.Ptr(action_kit_api.Error),
					Message: fmt.Sprintf("Invalid DNS error type: %s. Valid types are: NXDOMAIN, SERVFAIL, BOTH", errorType),
				}}, fmt.Errorf("invalid DNS error type: %s", errorType)
			}
		}

		filter, messages, err := mapToNetworkFilter(ctx, r, sidecar, request.Config, getRestrictedEndpoints(request))
		if err != nil {
			return nil, nil, err
		}

		interfaces := extutil.ToStringArray(request.Config["networkInterface"])
		if len(interfaces) == 0 {
			// For DNS error injection, we need to target the container's veth interface on the host
			// This allows us to run eBPF on the host and filter by container IP
			vethInterface, err := findContainerVethInterface(ctx, sidecar)
			if err != nil {
				return nil, []action_kit_api.Message{{
					Level:   extutil.Ptr(action_kit_api.Warn),
					Message: fmt.Sprintf("Could not detect container veth interface: %v. Using default interfaces.", err),
				}}, nil
			}
			if vethInterface != "" {
				interfaces = append(interfaces, vethInterface)
			} else {
				// Fallback to container's internal interfaces if veth detection fails
				ifs, errList := network.ListInterfaces(ctx, network.NewRuncRunner(r, sidecar))
				if errList != nil {
					return nil, nil, errList
				}
				for _, i := range ifs {
					interfaces = append(interfaces, i.Name)
				}
			}
		}

		if len(interfaces) == 0 {
			return nil, nil, fmt.Errorf("no network interfaces specified")
		}

		opts := &network.DNSErrorInjectionOpts{
			Filter:      filter,
			Interfaces:  interfaces,
			ErrorTypes:  errorTypes,
			ExecutionID: request.ExecutionId.String(),
		}

		// Validate that we have specific targets for safety
		if err := opts.ValidateTargeting(); err != nil {
			return nil, []action_kit_api.Message{{
				Level:   extutil.Ptr(action_kit_api.Error),
				Message: err.Error(),
			}}, err
		}

		return opts, messages, nil
	}
}

func dnsErrorInjectionDecode(data json.RawMessage) (network.Opts, error) {
	var opts network.DNSErrorInjectionOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}

// findContainerVethInterface detects the container's network interface on the host
func findContainerVethInterface(ctx context.Context, sidecar network.SidecarOpts) (string, error) {
	// Get the container's network namespace inode
	var netnsInode uint64
	for _, ns := range sidecar.TargetProcess.Namespaces {
		if ns.Type == "network" {
			netnsInode = ns.Inode
			break
		}
	}

	if netnsInode == 0 {
		return "", fmt.Errorf("no network namespace found")
	}

	// Use the host runner to list interfaces on the host
	hostRunner := network.NewProcessRunner()
	interfaces, err := network.ListInterfaces(ctx, hostRunner)
	if err != nil {
		return "", fmt.Errorf("failed to list host interfaces: %w", err)
	}

	// PRIORITY 1: Look for Docker bridge (docker0, br-*, etc.)
	// This is where container traffic actually flows in Docker's networking setup
	// TC hooks on the bridge are more reliable than on physical interfaces for container traffic
	for _, iface := range interfaces {
		if iface.Name == "docker0" || strings.HasPrefix(iface.Name, "br-") {
			return iface.Name, nil
		}
	}

	// PRIORITY 2: Look for the specific veth interface for this container
	// This is the most targeted approach
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "veth") {
			// TODO: Match the veth to the specific container's network namespace
			// For now, return the first veth (works if there's only one container)
			return iface.Name, nil
		}
	}

	// PRIORITY 3: Fallback to physical interfaces (eno1, eth0, etc.)
	// Note: TC hooks on physical interfaces often don't see container traffic
	// due to Docker's network architecture
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "eno") || strings.HasPrefix(iface.Name, "eth") {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found on host")
}
