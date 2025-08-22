package utils

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// GetParsedCidrs get a list of CIDRs as strings and return them as objects for 'net' library
// Failed CIDRs will be silently ignored
func GetParsedCidrs(cidrList []string) (parsedCidrList []*net.IPNet, err error) {

	errorsList := []error{}

	for _, trustedNetwork := range cidrList {
		_, netPtr, err := net.ParseCIDR(trustedNetwork)
		if err != nil {
			errorsList = append(errorsList, fmt.Errorf("invalid CIDR '%s': %s", trustedNetwork, err.Error()))
			continue
		}

		parsedCidrList = append(parsedCidrList, netPtr)
	}

	return parsedCidrList, errors.Join(errorsList...)
}

// IsTrustedIp checks whether an IP is inside a network (CIDR) or not
func IsTrustedIp(trustedNetworks []*net.IPNet, ip net.IP) (result bool) {
	for _, trustedCidrPtr := range trustedNetworks {
		if trustedCidrPtr.Contains(ip) {
			result = true
			break
		}
	}

	return result
}

// GetHopsFromChainedHops TODO
func GetHopsFromChainedHops(chainedHops string) (result []net.IP) {

	chainedHopsParts := strings.Split(chainedHops, ",")

	for _, hop := range chainedHopsParts {
		hop = strings.TrimSpace(hop)
		if hop == "" {
			continue
		}

		parsedHop := net.ParseIP(hop)
		if parsedHop != nil {
			result = append(result, parsedHop)
		}
	}

	return result
}

// GetRealClientIpFromXFF remove from XFF header all the IPs that are in trusted networks ranges and
// return the rightest surviving IP as the real client IP
func GetRealClientIpFromXFF(trustedNetworks []*net.IPNet, sourceHops []net.IP) (realClientIp net.IP, realClientIpFound bool) {
	var resultingSourceHops []net.IP

	// Look for the IPs into the CIDRs
	for _, sourceHop := range sourceHops {

		// Check if is current processed IP is trusted according to configured CIDRs
		if !IsTrustedIp(trustedNetworks, sourceHop) {
			resultingSourceHops = append(resultingSourceHops, sourceHop)
		}
	}

	// More than one? return the rightest one
	if len(resultingSourceHops) >= 1 {
		realClientIp = resultingSourceHops[len(resultingSourceHops)-1]
		return realClientIp, true
	}

	return nil, false
}
