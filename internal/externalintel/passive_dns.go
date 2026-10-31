package externalintel

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "sort"
 "strings"
 "time"

 "github.com/itsFuRy007/kem3t/internal/evidence"
)

const defaultOTXBaseURL="https://otx.alienvault.com/api/v1"
const maxPassiveDNSBytes=4<<20
const maxPassiveDNSRecords=500

// PassiveDNSRecord is a historical hostname-to-address observation from OTX.
type PassiveDNSRecord struct {
 Hostname string `json:"hostname"`
 Address string `json:"address"`
 RecordType string `json:"record_type"`
 FirstSeen string `json:"first_seen,omitempty"`
 LastSeen string `json:"last_seen,omitempty"`
 ASN string `json:"asn,omitempty"`
}

type PassiveDNSReport struct {
 Target string `json:"target"`
 Source string `json:"source"`
 RetrievedAt time.Time `json:"retrieved_at"`
 Records []PassiveDNSRecord `json:"records"`
 SourceRecordCount int `json:"source_record_count"`
 Truncated bool `json:"truncated"`
 Limitations []string `json:"limitations"`
}

type PassiveDNSClient struct {
 HTTPClient *http.Client
 BaseURL string
 APIKey string
 Timeout time.Duration
 Now func()time.Time
}

type otxPassiveDNSResponse struct {
 Count int `json:"count"`
 HasNext bool `json:"has_next"`
 PassiveDNS []struct{
  Address string `json:"address"`
  Hostname string `json:"hostname"`
  RecordType string `json:"record_type"`
  First string `json:"first"`
  Last string `json:"last"`
  ASN string `json:"asn"`
 } `json:"passive_dns"`
}

// LookupDomain retrieves historical A/AAAA observations from AlienVault OTX.
// The endpoint is anonymous-accessible subject to rate limits; APIKey is optional.
func(c *PassiveDNSClient)LookupDomain(ctx context.Context,rawTarget string)(PassiveDNSReport,error){
 if ctx==nil{return PassiveDNSReport{},fmt.Errorf("context is required")}
 target:=normalizeDomain(rawTarget);if !evidence.IsValidDomain(target){return PassiveDNSReport{},fmt.Errorf("target must be a valid DNS domain")}
 timeout:=c.Timeout;if timeout<=0{timeout=12*time.Second}
 ctx,cancel:=context.WithTimeout(ctx,timeout);defer cancel()
 base:=strings.TrimRight(strings.TrimSpace(c.BaseURL),"/");if base==""{base=defaultOTXBaseURL}
 parsed,err:=url.Parse(base);if err!=nil||parsed.Scheme!="https"||parsed.Host==""{return PassiveDNSReport{},fmt.Errorf("passive-DNS endpoint must be an absolute HTTPS URL")}
 endpoint:=strings.TrimRight(base,"/")+"/indicators/domain/"+url.PathEscape(target)+"/passive_dns"
 endpointURL,err:=url.Parse(endpoint);if err!=nil{return PassiveDNSReport{},err}
 query:=endpointURL.Query();query.Set("limit",fmt.Sprint(maxPassiveDNSRecords));endpointURL.RawQuery=query.Encode()
 client:=c.HTTPClient;if client==nil{client=&http.Client{Timeout:timeout,CheckRedirect:func(req *http.Request,via []*http.Request)error{if req.URL.Scheme!="https"{return fmt.Errorf("OTX redirects must use HTTPS")};if len(via)>=3{return fmt.Errorf("too many OTX redirects")};return nil}}}
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpointURL.String(),nil);if err!=nil{return PassiveDNSReport{},err}
 req.Header.Set("Accept","application/json");req.Header.Set("User-Agent","KEM3T-External-Intelligence/1.0 (research)")
 if key:=strings.TrimSpace(c.APIKey);key!=""{req.Header.Set("X-OTX-API-KEY",key)}
 resp,err:=doExternalRequest(ctx, client, req);if err!=nil{return PassiveDNSReport{},fmt.Errorf("query OTX passive DNS: %w",err)}
 if resp.StatusCode<200||resp.StatusCode>=300{status:=resp.StatusCode;_,_=io.Copy(io.Discard,io.LimitReader(resp.Body,2048));resp.Body.Close();return PassiveDNSReport{},fmt.Errorf("OTX passive-DNS source returned HTTP %d",status)}
 body,err:=io.ReadAll(io.LimitReader(resp.Body,maxPassiveDNSBytes+1));resp.Body.Close();if err!=nil{return PassiveDNSReport{},fmt.Errorf("read OTX response: %w",err)}
 if len(body)>maxPassiveDNSBytes{return PassiveDNSReport{},fmt.Errorf("OTX response exceeds %d bytes",maxPassiveDNSBytes)}
 var raw otxPassiveDNSResponse;if err:=json.Unmarshal(body,&raw);err!=nil{return PassiveDNSReport{},fmt.Errorf("decode OTX passive-DNS response: %w",err)}
 dedup:=map[string]PassiveDNSRecord{}
 for _,item:=range raw.PassiveDNS{
  hostname:=normalizeDomain(item.Hostname);if !evidence.IsValidDomain(hostname)||!inDomainScope(hostname,target){continue}
  ip:=net.ParseIP(strings.TrimSpace(item.Address));if ip==nil{continue}
  recordType:=strings.ToUpper(strings.TrimSpace(item.RecordType))
  if recordType=="A"&&ip.To4()==nil{continue};if recordType=="AAAA"&&ip.To4()!=nil{continue};if recordType!="A"&&recordType!="AAAA"{continue}
  record:=PassiveDNSRecord{Hostname:hostname,Address:ip.String(),RecordType:recordType,FirstSeen:strings.TrimSpace(item.First),LastSeen:strings.TrimSpace(item.Last),ASN:strings.TrimSpace(item.ASN)}
  key:=record.Hostname+"|"+record.Address+"|"+record.RecordType+"|"+record.FirstSeen+"|"+record.LastSeen
  dedup[key]=record
 }
 records:=make([]PassiveDNSRecord,0,len(dedup));for _,record:=range dedup{records=append(records,record)}
 sort.Slice(records,func(i,j int)bool{a,b:=records[i],records[j];if a.Hostname!=b.Hostname{return a.Hostname<b.Hostname};if a.Address!=b.Address{return a.Address<b.Address};if a.RecordType!=b.RecordType{return a.RecordType<b.RecordType};if a.FirstSeen!=b.FirstSeen{return a.FirstSeen<b.FirstSeen};return a.LastSeen<b.LastSeen})
 now:=time.Now().UTC();if c.Now!=nil{now=c.Now().UTC()}
 truncated:=raw.HasNext||raw.Count>len(raw.PassiveDNS)||len(raw.PassiveDNS)>=maxPassiveDNSRecords
 return PassiveDNSReport{Target:target,Source:parsed.Host,RetrievedAt:now,Records:records,SourceRecordCount:raw.Count,Truncated:truncated,Limitations:[]string{
  "Passive DNS records describe historical observations in OTX, not current resolution or a live service.",
  "First/last timestamps are provider-reported observation bounds and may be incomplete or delayed.",
  "An IP address observed for a hostname does not prove ownership, exclusive hosting, or maliciousness.",
  "OTX is one upstream intelligence source; labels from other aggregators may mirror the same underlying data.",
 }},nil
}

// RegisterPassiveDNSReport stores each passive-DNS fact and a timestamped observation.
func RegisterPassiveDNSReport(registry *evidence.Registry,report PassiveDNSReport)(int,error){
 if registry==nil{return 0,fmt.Errorf("evidence registry is required")}
 target:=normalizeDomain(report.Target);if !evidence.IsValidDomain(target){return 0,fmt.Errorf("passive-DNS target is invalid")}
 source:=strings.TrimSpace(report.Source);if source==""{return 0,fmt.Errorf("passive-DNS source is required")}
 if report.RetrievedAt.IsZero(){return 0,fmt.Errorf("passive-DNS retrieval timestamp is required")}
 added:=0
 for _,record:=range report.Records{
  hostname:=normalizeDomain(record.Hostname);ip:=net.ParseIP(strings.TrimSpace(record.Address));typ:=strings.ToUpper(strings.TrimSpace(record.RecordType))
  if !evidence.IsValidDomain(hostname)||!inDomainScope(hostname,target){return added,fmt.Errorf("passive-DNS hostname %q is invalid or outside target scope",record.Hostname)}
  if ip==nil{return added,fmt.Errorf("passive-DNS address %q is invalid",record.Address)}
  if typ=="A"&&ip.To4()==nil||typ=="AAAA"&&ip.To4()!=nil||(typ!="A"&&typ!="AAAA"){return added,fmt.Errorf("passive-DNS record type %q does not match address",typ)}
  details:=evidence.PassiveDNSDetails{Target:target,Hostname:hostname,Address:ip.String(),RecordType:typ,FirstSeen:strings.TrimSpace(record.FirstSeen),LastSeen:strings.TrimSpace(record.LastSeen),ASN:strings.TrimSpace(record.ASN),Source:source,Truncated:report.Truncated}
  value,err:=json.Marshal(details);if err!=nil{return added,err};sum:=sha256.Sum256(value);key:=hex.EncodeToString(sum[:])
  item:=evidence.Evidence{ID:"passive-dns:"+key,EntityID:target,Type:evidence.TypePassiveDNS,Value:string(value)}
  if err:=registry.AddEvidence(item);err!=nil&&!errors.Is(err,evidence.ErrEvidenceExists){return added,fmt.Errorf("register passive-DNS evidence: %w",err)}
  eventID:="passive-dns:"+key+":"+fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
  observation:=evidence.Observation{ID:"observation:"+eventID,EvidenceID:item.ID,Source:source,ObservedAt:report.RetrievedAt.UTC(),EventIDs:[]string{eventID}}
  if err:=registry.AddObservation(observation);err!=nil{if errors.Is(err,evidence.ErrObservationExists){continue};return added,fmt.Errorf("register passive-DNS observation: %w",err)}
  added++
 }
 return added,nil
}
