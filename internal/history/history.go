// Package history builds evidence-backed snapshots and deterministic timelines
// from completed collection runs.
package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

type Record struct {
	Key            string    `json:"key"`
	Type           evidence.Type `json:"type"`
	EntityID       string    `json:"entity_id"`
	ValueHash      string    `json:"value_hash"`
	EvidenceIDs    []string  `json:"evidence_ids"`
	ObservationIDs []string  `json:"observation_ids"`
	ObservedAt     time.Time `json:"observed_at"`
}

type Snapshot struct {
	RunID      string    `json:"run_id"`
	Target     string    `json:"target"`
	Collector  string    `json:"collector"`
	CollectedAt time.Time `json:"collected_at"`
	Records    []Record  `json:"records"`
}

type ChangeType string

const (
	ChangeAdded   ChangeType = "ADDED"
	ChangeRemoved ChangeType = "REMOVED"
	ChangeUpdated ChangeType = "UPDATED"
)

type Change struct {
	Target         string     `json:"target"`
	Collector      string     `json:"collector"`
	PreviousRunID  string     `json:"previous_run_id"`
	CurrentRunID   string     `json:"current_run_id"`
	Type           ChangeType `json:"type"`
	Key            string     `json:"key"`
	EvidenceIDs    []string   `json:"evidence_ids"`
	ObservationIDs []string   `json:"observation_ids"`
}

type Timeline struct {
	Snapshots []Snapshot `json:"snapshots"`
	Changes   []Change   `json:"changes"`
}

type Anomaly struct {
	Target    string    `json:"target"`
	Collector string    `json:"collector"`
	RunID     string    `json:"run_id"`
	Type      string    `json:"type"`
	Summary   string    `json:"summary"`
	ChangeCount int     `json:"change_count"`
}

func CollectorForEvidence(kind evidence.Type) string {
	switch kind {
	case evidence.TypeDNSAddress:
		return "dns"
	case evidence.TypeTCPPort:
		return "tcp"
	case evidence.TypeTLSCertificate:
		return "tls"
	case evidence.TypeHTTPService:
		return "http"
	default:
		return "unknown"
	}
}

func CollectorForRun(runID string) string {
	prefix, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(runID)), "-")
	if !ok { return "unknown" }
	switch prefix {
	case "dns", "tcp", "tls", "http":
		return prefix
	default:
		return "unknown"
	}
}

// BuildSnapshot captures only observations whose timestamps fall within the
// completed run. Missing observations are never synthesized into records.
func BuildSnapshot(run evidence.CollectionRun, records []evidence.Evidence, observations []evidence.Observation) (Snapshot, error) {
	if err := run.Validate(); err != nil { return Snapshot{}, fmt.Errorf("validate collection run: %w", err) }
	if run.Status != evidence.CollectionRunCompleted { return Snapshot{}, fmt.Errorf("cannot snapshot non-completed collection run %q", run.ID) }
	collector := CollectorForRun(run.ID)
	if collector == "unknown" { return Snapshot{}, fmt.Errorf("unsupported collection run type %q", run.ID) }

	target := NormalizeTarget(run.Target)
	evidenceByID := make(map[string]evidence.Evidence, len(records))
	for _, item := range records { evidenceByID[item.ID] = item }

	byKey := make(map[string]*Record)
	for _, observation := range observations {
		if observation.ObservedAt.Before(run.StartedAt) || observation.ObservedAt.After(run.FinishedAt) { continue }
		item, ok := evidenceByID[observation.EvidenceID]
		if !ok || NormalizeTarget(item.EntityID) != target || CollectorForEvidence(item.Type) != collector { continue }
		key, err := recordKey(item)
		if err != nil { return Snapshot{}, fmt.Errorf("build history key for evidence %q: %w", item.ID, err) }
		record, exists := byKey[key]
		if !exists {
			sum := sha256.Sum256([]byte(item.Value))
			record = &Record{Key:key, Type:item.Type, EntityID:item.EntityID, ValueHash:hex.EncodeToString(sum[:]), ObservedAt:observation.ObservedAt.UTC()}
			byKey[key] = record
		} else if observation.ObservedAt.After(record.ObservedAt) {
			sum := sha256.Sum256([]byte(item.Value))
			record.ValueHash = hex.EncodeToString(sum[:])
			record.ObservedAt = observation.ObservedAt.UTC()
		}
		record.EvidenceIDs = appendUnique(record.EvidenceIDs, item.ID)
		record.ObservationIDs = appendUnique(record.ObservationIDs, observation.ID)
	}
	result := Snapshot{RunID:run.ID, Target:target, Collector:collector, CollectedAt:run.FinishedAt.UTC(), Records:make([]Record,0,len(byKey))}
	for _, record := range byKey {
		sort.Strings(record.EvidenceIDs); sort.Strings(record.ObservationIDs)
		result.Records = append(result.Records, *record)
	}
	sort.Slice(result.Records,func(i,j int)bool{return result.Records[i].Key<result.Records[j].Key})
	if err := result.Validate(); err != nil { return Snapshot{}, fmt.Errorf("validate generated history snapshot: %w",err) }
	return result,nil
}

func (s Snapshot) Validate() error {
	if strings.TrimSpace(s.RunID)=="" || NormalizeTarget(s.Target)=="" { return fmt.Errorf("snapshot run ID and target are required") }
	if s.Collector!="dns" && s.Collector!="tcp" && s.Collector!="tls" && s.Collector!="http" { return fmt.Errorf("unsupported snapshot collector %q",s.Collector) }
	if s.CollectedAt.IsZero() { return fmt.Errorf("snapshot collection time is required") }
	seen:=make(map[string]struct{},len(s.Records))
	for i,r:=range s.Records {
		if strings.TrimSpace(r.Key)=="" || strings.TrimSpace(r.EntityID)=="" || strings.TrimSpace(r.ValueHash)=="" { return fmt.Errorf("snapshot record %d is incomplete",i) }
		if len(r.EvidenceIDs)==0 || len(r.ObservationIDs)==0 { return fmt.Errorf("snapshot record %q must retain evidence and observation references",r.Key) }
		if i>0 && s.Records[i-1].Key>=r.Key { return fmt.Errorf("snapshot records must be sorted and unique by key") }
		if _,ok:=seen[r.Key];ok{return fmt.Errorf("duplicate snapshot record key %q",r.Key)};seen[r.Key]=struct{}{}
	}
	return nil
}

func Compare(previous,current Snapshot) ([]Change,error) {
	if err:=previous.Validate();err!=nil{return nil,fmt.Errorf("validate previous snapshot: %w",err)}
	if err:=current.Validate();err!=nil{return nil,fmt.Errorf("validate current snapshot: %w",err)}
	if NormalizeTarget(previous.Target)!=NormalizeTarget(current.Target)||previous.Collector!=current.Collector{return nil,fmt.Errorf("snapshots must have the same target and collector")}
	old:=make(map[string]Record,len(previous.Records));for _,r:=range previous.Records{old[r.Key]=r}
	now:=make(map[string]Record,len(current.Records));for _,r:=range current.Records{now[r.Key]=r}
	result:=make([]Change,0)
	add:=func(kind ChangeType,key string,refs Record){result=append(result,Change{Target:current.Target,Collector:current.Collector,PreviousRunID:previous.RunID,CurrentRunID:current.RunID,Type:kind,Key:key,EvidenceIDs:append([]string(nil),refs.EvidenceIDs...),ObservationIDs:append([]string(nil),refs.ObservationIDs...)})}
	for key,r:=range now { prior,exists:=old[key];if !exists{add(ChangeAdded,key,r)}else if prior.ValueHash!=r.ValueHash{add(ChangeUpdated,key,r)} }
	for key,r:=range old { if _,exists:=now[key];!exists{add(ChangeRemoved,key,r)} }
	sort.Slice(result,func(i,j int)bool{if result[i].Key!=result[j].Key{return result[i].Key<result[j].Key};return result[i].Type<result[j].Type})
	return result,nil
}

func BuildTimeline(snapshots []Snapshot) (Timeline,error) {
	copied:=append([]Snapshot(nil),snapshots...)
	for _,s:=range copied{if err:=s.Validate();err!=nil{return Timeline{},err}}
	sort.Slice(copied,func(i,j int)bool{if copied[i].CollectedAt.Equal(copied[j].CollectedAt){return copied[i].RunID<copied[j].RunID};return copied[i].CollectedAt.Before(copied[j].CollectedAt)})
	result:=Timeline{Snapshots:copied,Changes:make([]Change,0)}
	last:=make(map[string]Snapshot)
	for _,current:=range copied {
		group:=current.Target+"\x00"+current.Collector
		if previous,ok:=last[group];ok {
			if current.CollectedAt.Before(previous.CollectedAt){return Timeline{},fmt.Errorf("history snapshots are not chronological")}
			changes,err:=Compare(previous,current);if err!=nil{return Timeline{},err}
			result.Changes=append(result.Changes,changes...)
		}
		last[group]=current
	}
	sort.Slice(result.Changes,func(i,j int)bool{if result.Changes[i].CurrentRunID!=result.Changes[j].CurrentRunID{return result.Changes[i].CurrentRunID<result.Changes[j].CurrentRunID};if result.Changes[i].Key!=result.Changes[j].Key{return result.Changes[i].Key<result.Changes[j].Key};return result.Changes[i].Type<result.Changes[j].Type})
	return result,nil
}

// DetectAnomalies reports high-change-volume runs as review signals, not
// security verdicts. A run must change at least five records and at least half
// of the larger snapshot to be reported.
func DetectAnomalies(timeline Timeline) []Anomaly {
	byRun:=make(map[string][]Change)
	for _,change:=range timeline.Changes { byRun[change.CurrentRunID]=append(byRun[change.CurrentRunID],change) }
	snapshots:=make(map[string]Snapshot)
	for _,s:=range timeline.Snapshots { snapshots[s.RunID]=s }
	result:=make([]Anomaly,0)
	for runID,changes:=range byRun {
		if len(changes)<5 { continue }
		current,ok:=snapshots[runID];if !ok{continue}
		var previous *Snapshot
		for i:=range timeline.Snapshots { s:=timeline.Snapshots[i];if s.RunID==changes[0].PreviousRunID { previous=&s;break } }
		if previous==nil{continue}
		larger:=len(previous.Records);if len(current.Records)>larger{larger=len(current.Records)}
		if larger==0 || float64(len(changes))/float64(larger)<0.5 {continue}
		result=append(result,Anomaly{Target:current.Target,Collector:current.Collector,RunID:runID,Type:"HIGH_CHANGE_VOLUME",Summary:fmt.Sprintf("%d changes affect at least half of the %d-record baseline/current snapshot; review collection context before interpreting.",len(changes),larger),ChangeCount:len(changes)})
	}
	sort.Slice(result,func(i,j int)bool{if result[i].RunID!=result[j].RunID{return result[i].RunID<result[j].RunID};return result[i].Type<result[j].Type})
	return result
}

func recordKey(item evidence.Evidence)(string,error){
	switch item.Type {
	case evidence.TypeDNSAddress:
		ip:=net.ParseIP(strings.TrimSpace(item.Value));if ip==nil{return "",fmt.Errorf("invalid DNS address")};return string(item.Type)+"|"+NormalizeTarget(item.EntityID)+"|"+ip.String(),nil
	case evidence.TypeTCPPort:
		var d evidence.TCPPortDetails;if err:=json.Unmarshal([]byte(item.Value),&d);err!=nil{return "",err};return fmt.Sprintf("%s|%s|%05d",item.Type,NormalizeTarget(item.EntityID),d.Port),nil
	case evidence.TypeTLSCertificate:
		var d evidence.TLSCertificateDetails;if err:=json.Unmarshal([]byte(item.Value),&d);err!=nil{return "",err};return fmt.Sprintf("%s|%s|%05d",item.Type,NormalizeTarget(item.EntityID),d.Port),nil
	case evidence.TypeHTTPService:
		var d evidence.HTTPServiceDetails;if err:=json.Unmarshal([]byte(item.Value),&d);err!=nil{return "",err};return fmt.Sprintf("%s|%s|%05d|%s",item.Type,NormalizeTarget(item.EntityID),d.Port,d.Scheme),nil
	default:return "",fmt.Errorf("unsupported evidence type %q",item.Type)
	}
}
// NormalizeTarget canonicalizes a hostname/IP or an absolute HTTP(S) URL to its host.
func NormalizeTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			return ""
		}
		target = parsed.Hostname()
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.String()
	}
	return strings.TrimSuffix(target, ".")
}
func appendUnique(values []string,value string)[]string{for _,v:=range values{if v==value{return values}};return append(values,value)}
