package extcontainer

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
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
		optsProvider: dnsErrorInjection(r, client),
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
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("How long should the DNS errors be injected?"),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(0),
			},
			{
				Name:         "dnsErrorTypes",
				Label:        "DNS Error Types",
				Description:  extutil.Ptr("Which DNS errors to inject?"),
				Type:         action_kit_api.ActionParameterTypeStringArray,
				DefaultValue: extutil.Ptr("[\"NXDOMAIN\"]"),
				Required:     extutil.Ptr(true),
				Options: extutil.Ptr([]action_kit_api.ParameterOption{
					action_kit_api.ExplicitParameterOption{
						Label: "Both (Random)",
						Value: "BOTH",
					},
					action_kit_api.ExplicitParameterOption{
						Label: "NXDOMAIN",
						Value: "NXDOMAIN",
					},
					action_kit_api.ExplicitParameterOption{
						Label: "SERVFAIL",
						Value: "SERVFAIL",
					},
				}),
				Order: extutil.Ptr(1),
			},
		},
	}
}

func dnsErrorInjection(r ociruntime.OciRuntime, client types.Client) networkOptsProvider {
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

		// For DNS error injection on containers, we MUST use the specific container IP
		// Get the container's IP address using Docker inspect (more reliable than netns introspection)
		var containerIP string

		// Extract container ID from the request target
		containerID := ""
		if targetName, ok := request.Target.Attributes["container.id"]; ok && len(targetName) > 0 {
			// Remove "docker://" prefix if present
			containerID = strings.TrimPrefix(targetName[0], "docker://")
		}

		if containerID != "" && client != nil {
			// Use container runtime API to get the container's IP
			containerIP, err := getContainerIPFromRuntime(ctx, client, containerID)
			if err != nil {
				log.Warn().
					Str("container_id", sidecar.IdSuffix).
					Str("runtime", string(client.Runtime())).
					Err(err).
					Msg("failed to get container IP from runtime API, falling back to netns introspection")
			} else {
				log.Info().
					Str("container_id", sidecar.IdSuffix).
					Str("runtime", string(client.Runtime())).
					Str("detected_ip_from_runtime", containerIP).
					Msg("detected container IP from runtime API for DNS error injection targeting")
			}
		}

		// Fallback: Get IP by introspecting the container's network namespace
		if containerIP == "" {
			containerRunner := network.NewRuncRunner(r, sidecar)
			containerInterfaces, err := network.ListInterfaces(ctx, containerRunner)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get container interfaces: %w", err)
			}

			// Find the container's IP from eth0
			for _, iface := range containerInterfaces {
				if iface.Name == "eth0" && len(iface.AddrInfo) > 0 {
					for _, addr := range iface.AddrInfo {
						if addr.Family == "inet" {
							containerIP = addr.Local
							break
						}
					}
				}
			}

			if containerIP != "" {
				log.Info().
					Str("container_id", sidecar.IdSuffix).
					Str("detected_ip_from_netns", containerIP).
					Msg("detected container IP from netns for DNS error injection targeting")
			}
		}

		if containerIP == "" {
			return nil, nil, fmt.Errorf("could not determine container IP address for DNS error injection")
		}

		// Override the config to use the container's specific IP
		// This ensures we only affect this container, not all containers on docker0
		configWithIP := make(map[string]interface{})
		for k, v := range request.Config {
			configWithIP[k] = v
		}
		// Must use []interface{} for compatibility with extutil.ToStringArray
		configWithIP["ip"] = []interface{}{containerIP}

		log.Debug().
			Str("container_id", sidecar.IdSuffix).
			Interface("config_ip", configWithIP["ip"]).
			Msg("overriding config with container IP")

		filter, messages, err := mapToNetworkFilter(ctx, r, sidecar, configWithIP, getRestrictedEndpoints(request))
		if err != nil {
			return nil, nil, err
		}

		interfaces := extutil.ToStringArray(request.Config["networkInterface"])
		if len(interfaces) == 0 {
			// Attach to docker bridge to reliably see DNS responses to the container IP
			hostRunner := network.NewProcessRunner()
			hostIfs, err := network.ListInterfaces(ctx, hostRunner)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to list host interfaces: %w", err)
			}

			// Prefer docker0, else br-*
			for _, i := range hostIfs {
				if i.Name == "docker0" {
					interfaces = append(interfaces, i.Name)
					break
				}
			}
			if len(interfaces) == 0 {
				for _, i := range hostIfs {
					if strings.HasPrefix(i.Name, "br-") {
						interfaces = append(interfaces, i.Name)
						break
					}
				}
			}

			// As last resort, still add docker0 name even if not listed (will error at attach if missing)
			if len(interfaces) == 0 {
				interfaces = append(interfaces, "docker0")
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
			IsContainer: true, // This is a container-level attack
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

// getContainerIPFromRuntime uses the container runtime API to get the container's primary IPv4 address
// This is more reliable than introspecting the network namespace
// Supports Docker, containerd, and CRI-O
func getContainerIPFromRuntime(ctx context.Context, client types.Client, containerID string) (string, error) {
	runtime := client.Runtime()

	switch runtime {
	case types.RuntimeDocker:
		return getContainerIPFromDocker(ctx, containerID)
	case types.RuntimeContainerd:
		return getContainerIPFromContainerd(ctx, containerID)
	case types.RuntimeCrio:
		return getContainerIPFromCrio(ctx, containerID)
	default:
		return "", fmt.Errorf("unsupported container runtime: %s", runtime)
	}
}

// getContainerIPFromDocker extracts the IP from Docker
func getContainerIPFromDocker(ctx context.Context, containerID string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker inspect failed: %w, output: %s", err, string(output))
	}

	ip := strings.TrimSpace(string(output))
	if ip == "" || ip == "<no value>" {
		return "", fmt.Errorf("no IP address found in docker inspect output")
	}

	return ip, nil
}

// getContainerIPFromContainerd extracts the IP from containerd via crictl or ctr
func getContainerIPFromContainerd(ctx context.Context, containerID string) (string, error) {
	// Try crictl first (most common for K8s environments)
	if _, err := exec.LookPath("crictl"); err == nil {
		return getContainerIPViaCrictl(ctx, containerID)
	}

	// Fallback to ctr (containerd CLI)
	if _, err := exec.LookPath("ctr"); err == nil {
		return getContainerIPViaCtr(ctx, containerID)
	}

	return "", fmt.Errorf("neither crictl nor ctr found for containerd runtime")
}

// getContainerIPFromCrio extracts the IP from CRI-O via crictl
func getContainerIPFromCrio(ctx context.Context, containerID string) (string, error) {
	return getContainerIPViaCrictl(ctx, containerID)
}

// getContainerIPViaCrictl uses crictl inspect to get the container IP
func getContainerIPViaCrictl(ctx context.Context, containerID string) (string, error) {
	// crictl inspect returns JSON with IP in different possible locations
	cmd := exec.CommandContext(ctx, "crictl", "inspect", containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("crictl inspect failed: %w, output: %s", err, string(output))
	}

	// Parse JSON to extract IP
	// Try multiple possible JSON paths: .info.network.ip, .status.network.ip
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return "", fmt.Errorf("failed to parse crictl output: %w", err)
	}

	// Try .info.network.ip
	if info, ok := result["info"].(map[string]interface{}); ok {
		if network, ok := info["network"].(map[string]interface{}); ok {
			if ip, ok := network["ip"].(string); ok && ip != "" {
				return ip, nil
			}
		}
	}

	// Try .status.network.ip
	if status, ok := result["status"].(map[string]interface{}); ok {
		if network, ok := status["network"].(map[string]interface{}); ok {
			if ip, ok := network["ip"].(string); ok && ip != "" {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no IP address found in crictl inspect output")
}

// getContainerIPViaCtr uses ctr (containerd CLI) to get the container IP
// This requires getting the PID and using nsenter
func getContainerIPViaCtr(ctx context.Context, containerID string) (string, error) {
	// Get the task PID
	cmd := exec.CommandContext(ctx, "ctr", "tasks", "ls")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ctr tasks ls failed: %w", err)
	}

	// Parse output to find PID for our container
	lines := strings.Split(string(output), "\n")
	var pid string
	for _, line := range lines {
		if strings.Contains(line, containerID) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid = fields[1]
				break
			}
		}
	}

	if pid == "" {
		return "", fmt.Errorf("could not find PID for container %s", containerID)
	}

	// Use nsenter to get the IP from within the container's network namespace
	cmd = exec.CommandContext(ctx, "nsenter", "-t", pid, "-n",
		"ip", "-4", "addr", "show", "eth0")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nsenter ip addr failed: %w, output: %s", err, string(output))
	}

	// Parse output to extract IP address
	// Example line: "    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0"
	lines = strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Extract IP before the /mask
				ipWithMask := fields[1]
				ip := strings.Split(ipWithMask, "/")[0]
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("could not parse IP from nsenter output")
}

// findContainerVethInterface detects the best network interface on the host for eBPF attachment
// to target this specific container's DNS traffic
func findContainerVethInterface(ctx context.Context, r ociruntime.OciRuntime, sidecar network.SidecarOpts) (string, error) {
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

	// Get all interfaces on the host
	hostRunner := network.NewProcessRunner()
	hostInterfaces, err := network.ListInterfaces(ctx, hostRunner)
	if err != nil {
		return "", fmt.Errorf("failed to list host interfaces: %w", err)
	}

	// IMPORTANT: We attach to docker0 (the bridge) rather than the specific veth interface
	// because:
	// 1. docker0 sees ALL container traffic, making packet capture reliable
	// 2. The eBPF program filters by the container's specific IP address, ensuring
	//    only the target container's DNS traffic is affected
	// 3. This approach is more robust than trying to identify the exact veth interface,
	//    especially in complex multi-container environments
	//
	// Even though multiple containers use docker0, the IP-based filtering in the eBPF
	// program ensures we only inject errors into DNS traffic for the targeted container.

	for _, iface := range hostInterfaces {
		if iface.Name == "docker0" {
			return "docker0", nil
		}
		// Also check for custom bridge networks (br-*)
		if strings.HasPrefix(iface.Name, "br-") {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no Docker bridge interface (docker0 or br-*) found on host")
}
