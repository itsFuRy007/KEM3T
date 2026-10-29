package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type NodeType string

const (
	NodeDomain         NodeType = "DOMAIN"
	NodeIP             NodeType = "IP_ADDRESS"
	NodeTLSCertificate NodeType = "TLS_CERTIFICATE"
	NodeTCPPort        NodeType = "TCP_PORT"
	NodeHTTPService    NodeType = "HTTP_SERVICE"
	NodeNetworkService NodeType = "NETWORK_SERVICE"
	NodeCTCertificate  NodeType = "CT_CERTIFICATE_RECORD"
	NodeRegistrar      NodeType = "REGISTRAR"
	NodeASN            NodeType = "AUTONOMOUS_SYSTEM"
	NodeNetworkPrefix  NodeType = "NETWORK_PREFIX"
	NodeThreatPulse    NodeType = "THREAT_INTELLIGENCE_PULSE"
)

type EdgeType string

const (
	EdgeResolvesTo          EdgeType = "RESOLVES_TO"
	EdgePresentsCertificate EdgeType = "PRESENTS_CERTIFICATE"
	EdgeHasOpenPort         EdgeType = "HAS_OPEN_PORT"
	EdgeServesHTTP          EdgeType = "SERVES_HTTP"
	EdgeHostsService        EdgeType = "HOSTS_SERVICE"
	EdgeCTSearchResult      EdgeType = "CT_SEARCH_RESULT"
	EdgeCTIncludesName      EdgeType = "CT_INCLUDES_DNS_NAME"
	EdgeRDAPNameServer      EdgeType = "RDAP_NAMESERVER"
	EdgeRDAPRegistrar       EdgeType = "RDAP_REGISTRAR"
	EdgeOriginatesFrom      EdgeType = "ORIGINATES_FROM_ASN"
	EdgeASNAnnouncesPrefix  EdgeType = "ASN_ANNOUNCES_PREFIX"
	EdgePassiveDNSResolvesTo EdgeType = "PASSIVE_DNS_RESOLVES_TO"
	EdgeIndicatorMentionedInPulse EdgeType = "INDICATOR_MENTIONED_IN_PULSE"
)

type Node struct {
	ID    string   `json:"id"`
	Type  NodeType `json:"type"`
	Value string   `json:"value"`
}

type Edge struct {
	ID             string   `json:"id"`
	Type           EdgeType `json:"type"`
	Source         string   `json:"source"`
	Target         string   `json:"target"`
	Port           int      `json:"port,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids"`
	ObservationIDs []string `json:"observation_ids"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Build creates a deterministic graph from DNS address evidence.
func Build(records []evidence.Evidence, observations []evidence.Observation) (Graph, error) {
	observationByEvidence := make(map[string][]string)
	seenObservations := make(map[string]struct{})

	for _, observation := range observations {
		if observation.ID != strings.TrimSpace(observation.ID) ||
			observation.EvidenceID != strings.TrimSpace(observation.EvidenceID) {
			return Graph{}, fmt.Errorf("observation IDs must not contain surrounding whitespace")
		}
		if err := observation.Validate(); err != nil {
			return Graph{}, fmt.Errorf("invalid observation %q: %w", observation.ID, err)
		}
		if _, exists := seenObservations[observation.ID]; exists {
			return Graph{}, fmt.Errorf("duplicate observation ID %q", observation.ID)
		}
		seenObservations[observation.ID] = struct{}{}
		observationByEvidence[observation.EvidenceID] = append(
			observationByEvidence[observation.EvidenceID],
			observation.ID,
		)
	}

	seenEvidence := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.ID != strings.TrimSpace(record.ID) {
			return Graph{}, fmt.Errorf("evidence IDs must not contain surrounding whitespace")
		}
		if err := record.Validate(); err != nil {
			return Graph{}, fmt.Errorf("invalid evidence %q: %w", record.ID, err)
		}
		if _, exists := seenEvidence[record.ID]; exists {
			return Graph{}, fmt.Errorf("duplicate evidence ID %q", record.ID)
		}
		seenEvidence[record.ID] = struct{}{}
	}

	for _, observation := range observations {
		if _, exists := seenEvidence[observation.EvidenceID]; !exists {
			return Graph{}, fmt.Errorf(
				"observation %q references missing evidence %q",
				observation.ID,
				observation.EvidenceID,
			)
		}
	}

	nodesByID := make(map[string]Node)
	edgesByID := make(map[string]*Edge)

	for _, record := range records {
		switch record.Type {
		case evidence.TypeDNSAddress:
			domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.EntityID)), ".")
			ip := net.ParseIP(strings.TrimSpace(record.Value))
			if !evidence.IsValidDomain(record.EntityID) || ip == nil {
				return Graph{}, fmt.Errorf("evidence %q has an invalid domain or IP address", record.ID)
			}

			address := ip.String()
			domainNode := Node{ID: "domain:" + domain, Type: NodeDomain, Value: domain}
			ipNode := Node{ID: "ip:" + address, Type: NodeIP, Value: address}

			nodesByID[domainNode.ID] = domainNode
			nodesByID[ipNode.ID] = ipNode

			edgeID := "resolves-to:" + domain + ":" + address
			edge, exists := edgesByID[edgeID]
			if !exists {
				edge = &Edge{
					ID:     edgeID,
					Type:   EdgeResolvesTo,
					Source: domainNode.ID,
					Target: ipNode.ID,
				}
				edgesByID[edgeID] = edge
			}

			edge.EvidenceIDs = appendUnique(edge.EvidenceIDs, record.ID)
			for _, observationID := range observationByEvidence[record.ID] {
				edge.ObservationIDs = appendUnique(edge.ObservationIDs, observationID)
			}

		case evidence.TypeTCPPort:
			var details evidence.TCPPortDetails
			if err := json.Unmarshal([]byte(record.Value), &details); err != nil {
				return Graph{}, fmt.Errorf("decode TCP evidence %q: %w", record.ID, err)
			}
			target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.EntityID)), ".")
			var host Node
			if ip := net.ParseIP(target); ip != nil {
				host = Node{ID: "ip:" + ip.String(), Type: NodeIP, Value: ip.String()}
			} else {
				host = Node{ID: "domain:" + target, Type: NodeDomain, Value: target}
			}
			portNode := Node{ID: fmt.Sprintf("tcp-port:%s:%d", target, details.Port), Type: NodeTCPPort, Value: fmt.Sprintf("%s:%d", target, details.Port)}
			nodesByID[host.ID] = host
			nodesByID[portNode.ID] = portNode
			edgeID := fmt.Sprintf("has-open-port:%s:%d", target, details.Port)
			edge, exists := edgesByID[edgeID]
			if !exists {
				edge = &Edge{ID: edgeID, Type: EdgeHasOpenPort, Source: host.ID, Target: portNode.ID, Port: details.Port}
				edgesByID[edgeID] = edge
			}
			edge.EvidenceIDs = appendUnique(edge.EvidenceIDs, record.ID)
			for _, observationID := range observationByEvidence[record.ID] {
				edge.ObservationIDs = appendUnique(edge.ObservationIDs, observationID)
			}

		case evidence.TypeHTTPService:
			var details evidence.HTTPServiceDetails
			if err := json.Unmarshal([]byte(record.Value), &details); err != nil {
				return Graph{}, fmt.Errorf("decode HTTP evidence %q: %w", record.ID, err)
			}
			target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.EntityID)), ".")
			var host Node
			if ip := net.ParseIP(target); ip != nil {
				host = Node{ID: "ip:" + ip.String(), Type: NodeIP, Value: ip.String()}
			} else {
				if !evidence.IsValidDomain(target) {
					return Graph{}, fmt.Errorf("HTTP evidence %q has an invalid target", record.ID)
				}
				host = Node{ID: "domain:" + target, Type: NodeDomain, Value: target}
			}
			serviceID := fmt.Sprintf("http-service:%s:%d:%s", target, details.Port, details.Scheme)
			service := Node{ID: serviceID, Type: NodeHTTPService, Value: fmt.Sprintf("%s://%s:%d", details.Scheme, target, details.Port)}
			nodesByID[host.ID] = host
			nodesByID[service.ID] = service
			edgeID := fmt.Sprintf("serves-http:%s:%d:%s", target, details.Port, details.Scheme)
			edge, exists := edgesByID[edgeID]
			if !exists {
				edge = &Edge{ID: edgeID, Type: EdgeServesHTTP, Source: host.ID, Target: service.ID, Port: details.Port}
				edgesByID[edgeID] = edge
			}
			edge.EvidenceIDs = appendUnique(edge.EvidenceIDs, record.ID)
			for _, observationID := range observationByEvidence[record.ID] {
				edge.ObservationIDs = appendUnique(edge.ObservationIDs, observationID)
			}

		case evidence.TypeTLSCertificate:
			var details evidence.TLSCertificateDetails
			if err := json.Unmarshal([]byte(record.Value), &details); err != nil {
				return Graph{}, fmt.Errorf("decode TLS evidence %q: %w", record.ID, err)
			}

			target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.EntityID)), ".")
			var hostNode Node
			if ip := net.ParseIP(target); ip != nil {
				hostNode = Node{ID: "ip:" + ip.String(), Type: NodeIP, Value: ip.String()}
			} else {
				if !evidence.IsValidDomain(target) {
					return Graph{}, fmt.Errorf("TLS evidence %q has an invalid target", record.ID)
				}
				hostNode = Node{ID: "domain:" + target, Type: NodeDomain, Value: target}
			}

			fingerprint := strings.ToLower(strings.TrimSpace(details.SHA256Fingerprint))
			certNode := Node{
				ID:    "tls-cert:" + fingerprint,
				Type:  NodeTLSCertificate,
				Value: fingerprint,
			}
			nodesByID[hostNode.ID] = hostNode
			nodesByID[certNode.ID] = certNode

			edgeID := fmt.Sprintf("presents-certificate:%s:%d:%s", target, details.Port, fingerprint)
			edge, exists := edgesByID[edgeID]
			if !exists {
				edge = &Edge{
					ID:     edgeID,
					Type:   EdgePresentsCertificate,
					Source: hostNode.ID,
					Target: certNode.ID,
					Port:   details.Port,
				}
				edgesByID[edgeID] = edge
			}
			edge.EvidenceIDs = appendUnique(edge.EvidenceIDs, record.ID)
			for _, observationID := range observationByEvidence[record.ID] {
				edge.ObservationIDs = appendUnique(edge.ObservationIDs, observationID)
			}
		case evidence.TypeCTDNSName:
			var details evidence.CTDNSNameDetails
			if err := json.Unmarshal([]byte(record.Value), &details); err != nil {
				return Graph{}, fmt.Errorf("decode CT evidence %q: %w", record.ID, err)
			}
			root := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(details.Target)), ".")
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(details.DNSName)), ".")
			rootNode := Node{ID: "domain:" + root, Type: NodeDomain, Value: root}
			nameNode := Node{ID: "domain:" + name, Type: NodeDomain, Value: name}
			certKey := details.Source + ":" + fmt.Sprint(details.CertificateID)
			if details.CertificateID <= 0 {
				certKey = details.Source + ":unknown:" + strings.TrimPrefix(record.ID, "ct-dns-name:")
			}
			certNode := Node{ID: "ct-cert:" + certKey, Type: NodeCTCertificate, Value: details.Source + "#" + fmt.Sprint(details.CertificateID)}
			if details.CertificateID <= 0 {
				certNode.Value = details.Source + "#unknown:" + strings.TrimPrefix(record.ID, "ct-dns-name:")
			}
			nodesByID[rootNode.ID] = rootNode
			nodesByID[nameNode.ID] = nameNode
			nodesByID[certNode.ID] = certNode

			searchEdgeID := "ct-search-result:" + root + ":" + certNode.ID
			searchEdge, exists := edgesByID[searchEdgeID]
			if !exists {
				searchEdge = &Edge{ID: searchEdgeID, Type: EdgeCTSearchResult, Source: rootNode.ID, Target: certNode.ID}
				edgesByID[searchEdgeID] = searchEdge
			}
			searchEdge.EvidenceIDs = appendUnique(searchEdge.EvidenceIDs, record.ID)
			for _, observationID := range observationByEvidence[record.ID] {
				searchEdge.ObservationIDs = appendUnique(searchEdge.ObservationIDs, observationID)
			}

			nameEdgeID := "ct-includes-name:" + certNode.ID + ":" + name
			nameEdge, exists := edgesByID[nameEdgeID]
			if !exists {
				nameEdge = &Edge{ID: nameEdgeID, Type: EdgeCTIncludesName, Source: certNode.ID, Target: nameNode.ID}
				edgesByID[nameEdgeID] = nameEdge
			}
			nameEdge.EvidenceIDs = appendUnique(nameEdge.EvidenceIDs, record.ID)
			for _, observationID := range observationByEvidence[record.ID] {
				nameEdge.ObservationIDs = appendUnique(nameEdge.ObservationIDs, observationID)
			}

		case evidence.TypeRDAPRegistration:
			var details evidence.RDAPRegistrationDetails
			if err := json.Unmarshal([]byte(record.Value), &details); err != nil {
				return Graph{}, fmt.Errorf("decode RDAP evidence %q: %w", record.ID, err)
			}
			target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(details.Target)), ".")
			if !evidence.IsValidDomain(target) { return Graph{}, fmt.Errorf("RDAP evidence %q has invalid target", record.ID) }
			domainNode := Node{ID:"domain:"+target,Type:NodeDomain,Value:target}
			nodesByID[domainNode.ID]=domainNode
			for _, rawNS := range details.NameServers {
				ns:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawNS)),".")
				if !evidence.IsValidDomain(ns){return Graph{},fmt.Errorf("RDAP evidence %q has invalid nameserver",record.ID)}
				nsNode:=Node{ID:"domain:"+ns,Type:NodeDomain,Value:ns}
				nodesByID[nsNode.ID]=nsNode
				edgeID:="rdap-nameserver:"+target+":"+ns
				edge,exists:=edgesByID[edgeID]
				if !exists { edge=&Edge{ID:edgeID,Type:EdgeRDAPNameServer,Source:domainNode.ID,Target:nsNode.ID};edgesByID[edgeID]=edge }
				edge.EvidenceIDs=appendUnique(edge.EvidenceIDs,record.ID)
				for _, observationID:=range observationByEvidence[record.ID]{edge.ObservationIDs=appendUnique(edge.ObservationIDs,observationID)}
			}
			if registrar:=strings.TrimSpace(details.Registrar);registrar!="" {
				sum:=sha256.Sum256([]byte(strings.ToLower(registrar)))
				registrarID:="registrar:"+hex.EncodeToString(sum[:])
				registrarNode:=Node{ID:registrarID,Type:NodeRegistrar,Value:registrar}
				nodesByID[registrarID]=registrarNode
				edgeID:="rdap-registrar:"+target+":"+registrarID
				edge:=&Edge{ID:edgeID,Type:EdgeRDAPRegistrar,Source:domainNode.ID,Target:registrarID}
				edge.EvidenceIDs=appendUnique(edge.EvidenceIDs,record.ID)
				for _, observationID:=range observationByEvidence[record.ID]{edge.ObservationIDs=appendUnique(edge.ObservationIDs,observationID)}
				edgesByID[edgeID]=edge
			}

		case evidence.TypeASNOrigin:
			var details evidence.ASNOriginDetails
			if err:=json.Unmarshal([]byte(record.Value),&details);err!=nil{return Graph{},fmt.Errorf("decode ASN evidence %q: %w",record.ID,err)}
			ip:=net.ParseIP(details.Target);if ip==nil{return Graph{},fmt.Errorf("ASN evidence %q has invalid IP target",record.ID)}
			ipNode:=Node{ID:"ip:"+ip.String(),Type:NodeIP,Value:ip.String()};nodesByID[ipNode.ID]=ipNode
			for _,asnRecord:=range details.Records{
				if asnRecord.ASN==0{return Graph{},fmt.Errorf("ASN evidence %q has invalid ASN",record.ID)}
				_,prefix,err:=net.ParseCIDR(asnRecord.Prefix);if err!=nil||!prefix.Contains(ip){return Graph{},fmt.Errorf("ASN evidence %q has invalid prefix",record.ID)}
				asnID:=fmt.Sprintf("asn:%d",asnRecord.ASN)
				asnNode:=Node{ID:asnID,Type:NodeASN,Value:fmt.Sprintf("AS%d",asnRecord.ASN)}
				prefixValue:=prefix.String();prefixID:="network-prefix:"+prefixValue
				prefixNode:=Node{ID:prefixID,Type:NodeNetworkPrefix,Value:prefixValue}
				nodesByID[asnID]=asnNode;nodesByID[prefixID]=prefixNode
				originID:=fmt.Sprintf("origin-asn:%s:%d",ip.String(),asnRecord.ASN)
				originEdge,exists:=edgesByID[originID];if !exists{originEdge=&Edge{ID:originID,Type:EdgeOriginatesFrom,Source:ipNode.ID,Target:asnID};edgesByID[originID]=originEdge}
				originEdge.EvidenceIDs=appendUnique(originEdge.EvidenceIDs,record.ID)
				for _,observationID:=range observationByEvidence[record.ID]{originEdge.ObservationIDs=appendUnique(originEdge.ObservationIDs,observationID)}
				announceID:=fmt.Sprintf("asn-announces-prefix:%d:%s",asnRecord.ASN,prefixValue)
				announceEdge,exists:=edgesByID[announceID];if !exists{announceEdge=&Edge{ID:announceID,Type:EdgeASNAnnouncesPrefix,Source:asnID,Target:prefixID};edgesByID[announceID]=announceEdge}
				announceEdge.EvidenceIDs=appendUnique(announceEdge.EvidenceIDs,record.ID)
				for _,observationID:=range observationByEvidence[record.ID]{announceEdge.ObservationIDs=appendUnique(announceEdge.ObservationIDs,observationID)}
			}

		case evidence.TypePassiveDNS:
			var details evidence.PassiveDNSDetails
			if err:=json.Unmarshal([]byte(record.Value),&details);err!=nil{return Graph{},fmt.Errorf("decode passive-DNS evidence %q: %w",record.ID,err)}
			hostname:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(details.Hostname)),".")
			ip:=net.ParseIP(details.Address);if !evidence.IsValidDomain(hostname)||ip==nil{return Graph{},fmt.Errorf("passive-DNS evidence %q has invalid hostname or IP",record.ID)}
			domainNode:=Node{ID:"domain:"+hostname,Type:NodeDomain,Value:hostname};ipNode:=Node{ID:"ip:"+ip.String(),Type:NodeIP,Value:ip.String()}
			nodesByID[domainNode.ID]=domainNode;nodesByID[ipNode.ID]=ipNode
			edgeID:="passive-dns-resolves:"+hostname+":"+ip.String()
			edge,exists:=edgesByID[edgeID];if !exists{edge=&Edge{ID:edgeID,Type:EdgePassiveDNSResolvesTo,Source:domainNode.ID,Target:ipNode.ID};edgesByID[edgeID]=edge}
			edge.EvidenceIDs=appendUnique(edge.EvidenceIDs,record.ID)
			for _,observationID:=range observationByEvidence[record.ID]{edge.ObservationIDs=appendUnique(edge.ObservationIDs,observationID)}

		case evidence.TypeThreatIntel:
			var details evidence.ThreatIntelDetails
			if err:=json.Unmarshal([]byte(record.Value),&details);err!=nil{return Graph{},fmt.Errorf("decode threat-intelligence evidence %q: %w",record.ID,err)}
			target:=strings.TrimSpace(details.Target)
			var indicator Node
			if ip:=net.ParseIP(target);ip!=nil{indicator=Node{ID:"ip:"+ip.String(),Type:NodeIP,Value:ip.String()}}else{target=strings.TrimSuffix(strings.ToLower(target),".");if !evidence.IsValidDomain(target){return Graph{},fmt.Errorf("threat-intelligence evidence %q has invalid target",record.ID)};indicator=Node{ID:"domain:"+target,Type:NodeDomain,Value:target}}
			nodesByID[indicator.ID]=indicator
			for _,pulse:=range details.Pulses{
				sum:=sha256.Sum256([]byte(strings.TrimSpace(pulse.ID)));pulseID:="threat-pulse:"+hex.EncodeToString(sum[:])
				pulseNode:=Node{ID:pulseID,Type:NodeThreatPulse,Value:strings.TrimSpace(pulse.Name)};nodesByID[pulseID]=pulseNode
				edgeID:="indicator-mentioned-in-pulse:"+indicator.ID+":"+pulseID
				edge,exists:=edgesByID[edgeID];if !exists{edge=&Edge{ID:edgeID,Type:EdgeIndicatorMentionedInPulse,Source:indicator.ID,Target:pulseID};edgesByID[edgeID]=edge}
				edge.EvidenceIDs=appendUnique(edge.EvidenceIDs,record.ID)
				for _,observationID:=range observationByEvidence[record.ID]{edge.ObservationIDs=appendUnique(edge.ObservationIDs,observationID)}
			}

		}
	}

	result := Graph{
		Nodes: make([]Node, 0, len(nodesByID)),
		Edges: make([]Edge, 0, len(edgesByID)),
	}

	for _, node := range nodesByID {
		result.Nodes = append(result.Nodes, node)
	}
	sort.Slice(result.Nodes, func(i, j int) bool {
		return result.Nodes[i].ID < result.Nodes[j].ID
	})

	for _, edge := range edgesByID {
		sort.Strings(edge.EvidenceIDs)
		sort.Strings(edge.ObservationIDs)
		result.Edges = append(result.Edges, *edge)
	}
	sort.Slice(result.Edges, func(i, j int) bool {
		return result.Edges[i].ID < result.Edges[j].ID
	})

	if err := result.Validate(); err != nil {
		return Graph{}, fmt.Errorf("validate generated graph: %w", err)
	}
	return result, nil
}

// BuildFromRegistry builds a graph from the evidence registry.
func BuildFromRegistry(registry *evidence.Registry) (Graph, error) {
	if registry == nil {
		return Graph{}, fmt.Errorf("evidence registry is required")
	}
	return Build(registry.AllEvidence(), registry.AllObservations())
}

func (g Graph) Validate() error {
	nodes := make(map[string]Node, len(g.Nodes))

	for _, node := range g.Nodes {
		if strings.TrimSpace(node.ID) == "" || strings.TrimSpace(node.Value) == "" {
			return fmt.Errorf("node ID and value are required")
		}

		switch node.Type {
		case NodeDomain:
			value := strings.ToLower(strings.TrimSpace(node.Value))
			if !evidence.IsValidDomain(node.Value) || value != node.Value || node.ID != "domain:"+value {
				return fmt.Errorf("domain node %q is invalid or not normalized", node.ID)
			}
		case NodeIP:
			ip := net.ParseIP(node.Value)
			if ip == nil || ip.String() != node.Value || node.ID != "ip:"+node.Value {
				return fmt.Errorf("IP node %q is not normalized", node.ID)
			}
		case NodeNetworkService:
			if !strings.HasPrefix(node.ID, "service:") || strings.TrimSpace(node.Value) == "" {
				return fmt.Errorf("network service node %q has an invalid identity", node.ID)
			}
		case NodeHTTPService:
			if !strings.HasPrefix(node.ID, "http-service:") || !strings.Contains(node.Value, "://") {
				return fmt.Errorf("HTTP service node %q has an invalid identity", node.ID)
			}
		case NodeTCPPort:
			if !strings.HasPrefix(node.ID, "tcp-port:") {
				return fmt.Errorf("TCP port node %q has an invalid identity", node.ID)
			}
		case NodeThreatPulse:
			if !strings.HasPrefix(node.ID,"threat-pulse:")||strings.TrimSpace(node.Value)==""{return fmt.Errorf("threat pulse node %q has an invalid identity",node.ID)}
		case NodeASN:
			if !strings.HasPrefix(node.ID,"asn:") || !strings.HasPrefix(node.Value,"AS") { return fmt.Errorf("ASN node %q has an invalid identity",node.ID) }
		case NodeNetworkPrefix:
			_,prefix,err:=net.ParseCIDR(node.Value);if err!=nil||node.ID!="network-prefix:"+prefix.String(){return fmt.Errorf("network-prefix node %q has an invalid identity",node.ID)}
		case NodeRegistrar:
			if !strings.HasPrefix(node.ID, "registrar:") || strings.TrimSpace(node.Value) == "" { return fmt.Errorf("registrar node %q has an invalid identity", node.ID) }
		case NodeCTCertificate:
			if !strings.HasPrefix(node.ID, "ct-cert:") || !strings.Contains(node.Value, "#") {
				return fmt.Errorf("CT certificate node %q has an invalid identity", node.ID)
			}
		case NodeTLSCertificate:
			fingerprint := strings.ToLower(strings.TrimSpace(node.Value))
			if len(fingerprint) != 64 || fingerprint != node.Value || node.ID != "tls-cert:"+fingerprint {
				return fmt.Errorf("TLS certificate node %q is invalid or not normalized", node.ID)
			}
			if _, err := hex.DecodeString(fingerprint); err != nil {
				return fmt.Errorf("TLS certificate node %q has an invalid fingerprint", node.ID)
			}
		default:
			return fmt.Errorf("node %q has unsupported type %q", node.ID, node.Type)
		}

		if _, exists := nodes[node.ID]; exists {
			return fmt.Errorf("duplicate node ID %q", node.ID)
		}
		nodes[node.ID] = node
	}

	seenEdges := make(map[string]struct{}, len(g.Edges))
	for _, edge := range g.Edges {
		if strings.TrimSpace(edge.ID) == "" {
			return fmt.Errorf("edge ID is required")
		}
		if _, exists := seenEdges[edge.ID]; exists {
			return fmt.Errorf("duplicate edge ID %q", edge.ID)
		}
		seenEdges[edge.ID] = struct{}{}

		if len(edge.EvidenceIDs) == 0 {
			return fmt.Errorf("edge %q must reference evidence", edge.ID)
		}

		source, sourceExists := nodes[edge.Source]
		target, targetExists := nodes[edge.Target]
		if !sourceExists || !targetExists {
			return fmt.Errorf("edge %q references a missing node", edge.ID)
		}
		switch edge.Type {
		case EdgeResolvesTo:
			if source.Type != NodeDomain || target.Type != NodeIP || edge.Port != 0 {
				return fmt.Errorf("edge %q has invalid DNS type or endpoints", edge.ID)
			}
			if edge.ID != "resolves-to:"+source.Value+":"+target.Value {
				return fmt.Errorf("edge %q has an invalid identity", edge.ID)
			}
		case EdgeHasOpenPort:
			if (source.Type != NodeDomain && source.Type != NodeIP) || target.Type != NodeTCPPort {
				return fmt.Errorf("edge %q has invalid TCP endpoints", edge.ID)
			}
			if edge.Port < 1 || edge.Port > 65535 {
				return fmt.Errorf("edge %q has an invalid TCP port", edge.ID)
			}
			expectedID := fmt.Sprintf("has-open-port:%s:%d", source.Value, edge.Port)
			if edge.ID != expectedID || target.ID != fmt.Sprintf("tcp-port:%s:%d", source.Value, edge.Port) || target.Value != fmt.Sprintf("%s:%d", source.Value, edge.Port) {
				return fmt.Errorf("edge %q has an invalid TCP identity", edge.ID)
			}
		case EdgeServesHTTP:
			if (source.Type != NodeDomain && source.Type != NodeIP) || target.Type != NodeHTTPService {
				return fmt.Errorf("edge %q has invalid HTTP endpoints", edge.ID)
			}
			if edge.Port < 1 || edge.Port > 65535 {
				return fmt.Errorf("edge %q has an invalid HTTP port", edge.ID)
			}
			prefix := fmt.Sprintf("http-service:%s:%d:", source.Value, edge.Port)
			if !strings.HasPrefix(target.ID, prefix) {
				return fmt.Errorf("edge %q has an invalid HTTP service identity", edge.ID)
			}
			scheme := strings.TrimPrefix(target.ID, prefix)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("edge %q has an invalid HTTP scheme", edge.ID)
			}
			expectedID := fmt.Sprintf("serves-http:%s:%d:%s", source.Value, edge.Port, scheme)
			if edge.ID != expectedID || target.Value != fmt.Sprintf("%s://%s:%d", scheme, source.Value, edge.Port) {
				return fmt.Errorf("edge %q has an invalid HTTP identity", edge.ID)
			}
		case EdgeHostsService:
			if (source.Type != NodeDomain && source.Type != NodeIP) || target.Type != NodeNetworkService {
				return fmt.Errorf("edge %q has invalid service endpoints", edge.ID)
			}
			if edge.Port < 1 || edge.Port > 65535 {
				return fmt.Errorf("edge %q has an invalid service port", edge.ID)
			}
			servicePrefix := fmt.Sprintf("service:%s:%d:", source.Value, edge.Port)
			if !strings.HasPrefix(target.ID, servicePrefix) {
				return fmt.Errorf("edge %q has an invalid service identity", edge.ID)
			}
			application := strings.TrimPrefix(target.ID, servicePrefix)
			if application == "" || edge.ID != fmt.Sprintf("hosts-service:%s:%d:%s", source.Value, edge.Port, application) {
				return fmt.Errorf("edge %q has an invalid service identity", edge.ID)
			}
		case EdgeIndicatorMentionedInPulse:
			if (source.Type!=NodeDomain&&source.Type!=NodeIP)||target.Type!=NodeThreatPulse||edge.Port!=0||edge.ID!="indicator-mentioned-in-pulse:"+source.ID+":"+target.ID{return fmt.Errorf("edge %q has invalid threat-pulse identity or endpoints",edge.ID)}
		case EdgePassiveDNSResolvesTo:
			if source.Type!=NodeDomain||target.Type!=NodeIP||edge.Port!=0||edge.ID!="passive-dns-resolves:"+source.Value+":"+target.Value{return fmt.Errorf("edge %q has invalid passive-DNS identity or endpoints",edge.ID)}
		case EdgeOriginatesFrom:
			if source.Type!=NodeIP||target.Type!=NodeASN||edge.Port!=0||edge.ID!="origin-asn:"+source.Value+":"+strings.TrimPrefix(target.ID,"asn:"){return fmt.Errorf("edge %q has invalid origin-ASN identity or endpoints",edge.ID)}
		case EdgeASNAnnouncesPrefix:
			if source.Type!=NodeASN||target.Type!=NodeNetworkPrefix||edge.Port!=0||edge.ID!="asn-announces-prefix:"+strings.TrimPrefix(source.ID,"asn:")+":"+target.Value{return fmt.Errorf("edge %q has invalid ASN-prefix identity or endpoints",edge.ID)}
		case EdgeRDAPNameServer:
			if source.Type!=NodeDomain || target.Type!=NodeDomain || edge.Port!=0 || edge.ID!="rdap-nameserver:"+source.Value+":"+target.Value { return fmt.Errorf("edge %q has invalid RDAP nameserver identity or endpoints",edge.ID) }
		case EdgeRDAPRegistrar:
			if source.Type!=NodeDomain || target.Type!=NodeRegistrar || edge.Port!=0 || edge.ID!="rdap-registrar:"+source.Value+":"+target.ID { return fmt.Errorf("edge %q has invalid RDAP registrar identity or endpoints",edge.ID) }
		case EdgeCTSearchResult:
			if source.Type != NodeDomain || target.Type != NodeCTCertificate || edge.Port != 0 {
				return fmt.Errorf("edge %q has invalid CT search-result endpoints", edge.ID)
			}
			if edge.ID != "ct-search-result:"+source.Value+":"+target.ID {
				return fmt.Errorf("edge %q has an invalid CT search-result identity", edge.ID)
			}
		case EdgeCTIncludesName:
			if source.Type != NodeCTCertificate || target.Type != NodeDomain || edge.Port != 0 {
				return fmt.Errorf("edge %q has invalid CT name endpoints", edge.ID)
			}
			if edge.ID != "ct-includes-name:"+source.ID+":"+target.Value {
				return fmt.Errorf("edge %q has an invalid CT name identity", edge.ID)
			}
		case EdgePresentsCertificate:
			if (source.Type != NodeDomain && source.Type != NodeIP) || target.Type != NodeTLSCertificate {
				return fmt.Errorf("edge %q has invalid TLS endpoints", edge.ID)
			}
			if edge.Port < 1 || edge.Port > 65535 {
				return fmt.Errorf("edge %q has an invalid TLS port", edge.ID)
			}
			expectedID := fmt.Sprintf("presents-certificate:%s:%d:%s", source.Value, edge.Port, target.Value)
			if edge.ID != expectedID {
				return fmt.Errorf("edge %q has an invalid TLS identity", edge.ID)
			}
		default:
			return fmt.Errorf("edge %q has unsupported type %q", edge.ID, edge.Type)
		}
		if !isSortedUnique(edge.EvidenceIDs) || !isSortedUnique(edge.ObservationIDs) {
			return fmt.Errorf("edge %q references must be sorted and unique", edge.ID)
		}
	}

	if !sort.SliceIsSorted(g.Nodes, func(i, j int) bool {
		return g.Nodes[i].ID < g.Nodes[j].ID
	}) {
		return fmt.Errorf("graph nodes must be sorted by ID")
	}
	if !sort.SliceIsSorted(g.Edges, func(i, j int) bool {
		return g.Edges[i].ID < g.Edges[j].ID
	}) {
		return fmt.Errorf("graph edges must be sorted by ID")
	}
	return nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func isSortedUnique(values []string) bool {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
		if i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

// AttachServices adds normalized service nodes and host-to-service relationships
// to an existing infrastructure graph. Services without evidence references
// are skipped because graph relationships must remain evidence-backed.
func AttachServices(g Graph, services []observations.Service) (Graph, error) {
	nodes := make(map[string]Node, len(g.Nodes))
	edges := make(map[string]Edge, len(g.Edges))
	for _, node := range g.Nodes {
		nodes[node.ID] = node
	}
	for _, edge := range g.Edges {
		edges[edge.ID] = edge
	}
	for _, service := range services {
		target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(service.Target)), ".")
		if target == "" || service.Port < 1 || service.Port > 65535 || len(service.EvidenceIDs) == 0 {
			continue
		}
		var host Node
		if ip := net.ParseIP(target); ip != nil {
			host = Node{ID: "ip:" + ip.String(), Type: NodeIP, Value: ip.String()}
		} else {
			if !evidence.IsValidDomain(target) {
				return Graph{}, fmt.Errorf("service %q has invalid target %q", service.ID, target)
			}
			host = Node{ID: "domain:" + target, Type: NodeDomain, Value: target}
		}
		serviceID := fmt.Sprintf("service:%s:%d:%s", target, service.Port, service.Application)
		if service.Application == "" {
			serviceID = fmt.Sprintf("service:%s:%d:unknown", target, service.Port)
		}
		serviceNode := Node{ID: serviceID, Type: NodeNetworkService, Value: fmt.Sprintf("%s:%d (%s)", target, service.Port, service.Application)}
		if service.Application == "" {
			serviceNode.Value = fmt.Sprintf("%s:%d (unknown application)", target, service.Port)
		}
		nodes[host.ID] = host
		nodes[serviceNode.ID] = serviceNode
		edgeID := fmt.Sprintf("hosts-service:%s:%d:%s", target, service.Port, strings.TrimPrefix(serviceID, fmt.Sprintf("service:%s:%d:", target, service.Port)))
		edge := edges[edgeID]
		edge.ID, edge.Type, edge.Source, edge.Target, edge.Port = edgeID, EdgeHostsService, host.ID, serviceNode.ID, service.Port
		for _, evidenceID := range service.EvidenceIDs {
			edge.EvidenceIDs = appendUnique(edge.EvidenceIDs, evidenceID)
		}
		sort.Strings(edge.EvidenceIDs)
		edge.EvidenceIDs = uniqueStrings(edge.EvidenceIDs)
		edges[edgeID] = edge
	}
	result := Graph{Nodes: make([]Node, 0, len(nodes)), Edges: make([]Edge, 0, len(edges))}
	for _, node := range nodes {
		result.Nodes = append(result.Nodes, node)
	}
	for _, edge := range edges {
		result.Edges = append(result.Edges, edge)
	}
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	sort.Slice(result.Edges, func(i, j int) bool { return result.Edges[i].ID < result.Edges[j].ID })
	if err := result.Validate(); err != nil {
		return Graph{}, fmt.Errorf("validate graph with services: %w", err)
	}
	return result, nil
}

func uniqueStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
