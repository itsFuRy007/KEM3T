package externalintel

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "strings"
 "time"

 "github.com/itsFuRy007/kem3t/internal/evidence"
)

const (
 defaultASNDNSOverHTTPS = "https://cloudflare-dns.com/dns-query"
 defaultASNBootstrap = "https://data.iana.org/rdap/asn.json"
)

// ASNRecord combines an origin mapping with the corresponding RDAP autonomous-system record.
// MappingSource and RDAPSource are explicit because these are distinct upstream data paths.
type ASNRecord struct {
 ASN uint32 `json:"asn"`
 Prefix string `json:"prefix"`
 Country string `json:"country,omitempty"`
 Registry string `json:"registry,omitempty"`
 Allocated string `json:"allocated,omitempty"`
 NetworkName string `json:"network_name,omitempty"`
 Handle string `json:"handle,omitempty"`
 MappingSource string `json:"mapping_source"`
 RDAPSource string `json:"rdap_source"`
}

type ASNReport struct {
 Target string `json:"target"`
 RetrievedAt time.Time `json:"retrieved_at"`
 Records []ASNRecord `json:"records"`
 Limitations []string `json:"limitations"`
}

type ASNClient struct {
 HTTPClient *http.Client
 DNSOverHTTPS string
 BootstrapURL string
 Timeout time.Duration
 Now func() time.Time
}

type dohResponse struct {
 Status int `json:"Status"`
 Answer []struct { Name string `json:"name"`; Type int `json:"type"`; Data string `json:"data"` } `json:"Answer"`
}
type asnBootstrap struct { Services [][]json.RawMessage `json:"services"` }
type asnRDAPResponse struct {
 Name string `json:"name"`
 Handle string `json:"handle"`
 StartAutnum uint32 `json:"startAutnum"`
 EndAutnum uint32 `json:"endAutnum"`
 Entities []struct { Roles []string `json:"roles"`; VCard []any `json:"vcardArray"` } `json:"entities"`
}

// LookupIP resolves an IP's origin ASN using Team Cymru's origin DNS data through
// DNS-over-HTTPS, then enriches each ASN using the IANA-selected authoritative RDAP service.
func (c *ASNClient) LookupIP(ctx context.Context, rawIP string) (ASNReport,error) {
 if ctx==nil{return ASNReport{},fmt.Errorf("context is required")}
 ip:=net.ParseIP(strings.TrimSpace(rawIP));if ip==nil{return ASNReport{},fmt.Errorf("target must be an IP address")}
 if ip.IsPrivate()||ip.IsLoopback()||ip.IsLinkLocalUnicast()||ip.IsLinkLocalMulticast()||ip.IsMulticast()||ip.IsUnspecified(){return ASNReport{},fmt.Errorf("ASN origin lookup requires a globally routable IP address")}
 timeout:=c.Timeout;if timeout<=0{timeout=15*time.Second}
 ctx,cancel:=context.WithTimeout(ctx,timeout);defer cancel()
 client:=c.HTTPClient;if client==nil{client=&http.Client{Timeout:timeout}}
 doh:=strings.TrimSpace(c.DNSOverHTTPS);if doh==""{doh=defaultASNDNSOverHTTPS}
 parsed,err:=url.Parse(doh);if err!=nil||parsed.Scheme!="https"||parsed.Host==""{return ASNReport{},fmt.Errorf("ASN DNS-over-HTTPS endpoint must be absolute HTTPS")}
 qname:=cymruOriginName(ip)
 query,err:=url.Parse(doh);if err!=nil{return ASNReport{},err}
 params:=query.Query();params.Set("name",qname);params.Set("type","TXT");query.RawQuery=params.Encode()
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,query.String(),nil);if err!=nil{return ASNReport{},err}
 req.Header.Set("Accept","application/dns-json");req.Header.Set("User-Agent","KEM3T-External-Intelligence/1.0 (research)")
 resp,err:=client.Do(req);if err!=nil{return ASNReport{},fmt.Errorf("query origin ASN mapping: %w",err)}
 if resp.StatusCode<200||resp.StatusCode>=300{resp.Body.Close();return ASNReport{},fmt.Errorf("origin ASN DNS returned HTTP %d",resp.StatusCode)}
 body,readErr:=io.ReadAll(io.LimitReader(resp.Body,(1<<20)+1));resp.Body.Close();if readErr!=nil{return ASNReport{},readErr};if len(body)>1<<20{return ASNReport{},fmt.Errorf("origin ASN DNS response exceeds 1048576 bytes")}
 var dns dohResponse;if err:=json.Unmarshal(body,&dns);err!=nil{return ASNReport{},fmt.Errorf("decode ASN DNS response: %w",err)}
 if dns.Status!=0{return ASNReport{},fmt.Errorf("origin ASN DNS returned status %d",dns.Status)}
 mappings:=map[uint32]ASNRecord{}
 for _,answer:=range dns.Answer{
  if answer.Type!=16{continue}
  raw:=strings.Trim(strings.TrimSpace(answer.Data),"\"")
  fields:=strings.Split(raw,"|");if len(fields)<2{continue}
  asnText:=strings.TrimSpace(fields[0]);asnText=strings.TrimPrefix(strings.ToUpper(asnText),"AS")
  number,err:=strconv.ParseUint(asnText,10,32);if err!=nil||number==0{continue}
  prefix:=strings.TrimSpace(fields[1]);_,network,err:=net.ParseCIDR(prefix);if err!=nil||!network.Contains(ip){continue}
  record:=ASNRecord{ASN:uint32(number),Prefix:network.String(),MappingSource:"Team Cymru origin DNS via Cloudflare DNS-over-HTTPS"}
  if len(fields)>2{record.Country=strings.TrimSpace(fields[2])};if len(fields)>3{record.Registry=strings.TrimSpace(fields[3])};if len(fields)>4{record.Allocated=strings.TrimSpace(fields[4])}
  mappings[record.ASN]=record
 }
 if len(mappings)==0{return ASNReport{},fmt.Errorf("no valid origin ASN mapping returned for %s",ip.String())}
 bootstrapURL:=strings.TrimSpace(c.BootstrapURL);if bootstrapURL==""{bootstrapURL=defaultASNBootstrap}
 bp,err:=url.Parse(bootstrapURL);if err!=nil||bp.Scheme!="https"||bp.Host==""{return ASNReport{},fmt.Errorf("ASN RDAP bootstrap URL must be absolute HTTPS")}
 bootstrapBody,err:=rdapGET(ctx,client,bootstrapURL);if err!=nil{return ASNReport{},fmt.Errorf("fetch ASN RDAP bootstrap: %w",err)}
 var bootstrap asnBootstrap;if err:=json.Unmarshal(bootstrapBody,&bootstrap);err!=nil{return ASNReport{},fmt.Errorf("decode ASN RDAP bootstrap: %w",err)}
 asns:=make([]uint32,0,len(mappings));for asn:=range mappings{asns=append(asns,asn)}
 sortUint32(asns)
 records:=make([]ASNRecord,0,len(asns))
 for _,asn:=range asns{
  record:=mappings[asn]
  serviceURL,err:=selectASNService(bootstrap,asn);if err!=nil{return ASNReport{},err}
  endpoint,err:=url.Parse(serviceURL);if err!=nil{return ASNReport{},err}
  endpoint.Path=strings.TrimRight(endpoint.Path,"/")+"/autnum/"+strconv.FormatUint(uint64(asn),10)
  rdapBody,err:=rdapGET(ctx,client,endpoint.String());if err!=nil{return ASNReport{},fmt.Errorf("query RDAP for AS%d: %w",asn,err)}
  var raw asnRDAPResponse;if err:=json.Unmarshal(rdapBody,&raw);err!=nil{return ASNReport{},fmt.Errorf("decode RDAP for AS%d: %w",asn,err)}
  if raw.StartAutnum!=0&&(asn<raw.StartAutnum||asn>raw.EndAutnum){return ASNReport{},fmt.Errorf("ASN RDAP response range does not contain AS%d",asn)}
  record.Handle=strings.TrimSpace(raw.Handle);record.NetworkName=strings.TrimSpace(raw.Name)
  if record.NetworkName==""{for _,entity:=range raw.Entities{registrar:=false;for _,role:=range entity.Roles{if strings.EqualFold(role,"registrant")||strings.EqualFold(role,"administrative"){registrar=true}};if registrar{record.NetworkName=rdapRegistrarLabel(entity.VCard);if record.NetworkName!=""{break}}}}
  record.RDAPSource=endpoint.Host
  records=append(records,record)
 }
 now:=time.Now().UTC();if c.Now!=nil{now=c.Now().UTC()}
 return ASNReport{Target:ip.String(),RetrievedAt:now,Records:records,Limitations:[]string{
  "Origin ASN mappings can be missing, stale, or reflect routing announcements rather than legal ownership.",
  "RDAP network names are registry-provided labels and do not independently prove control of an IP or host.",
  "Multiple origin ASNs may be legitimate; this result is a routing lead, not a security or reputation verdict.",
 }},nil
}

func cymruOriginName(ip net.IP)string{
 if v4:=ip.To4();v4!=nil{return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com",v4[3],v4[2],v4[1],v4[0])}
 hexIP:=fmt.Sprintf("%x",ip.To16());parts:=make([]string,0,32);for i:=len(hexIP)-1;i>=0;i--{parts=append(parts,string(hexIP[i]))};return strings.Join(parts,".")+".origin6.asn.cymru.com"
}

func selectASNService(bootstrap asnBootstrap,asn uint32)(string,error){
 for _,service:=range bootstrap.Services{
  if len(service)!=2{continue};var ranges,urls []string
  if json.Unmarshal(service[0],&ranges)!=nil||json.Unmarshal(service[1],&urls)!=nil{continue}
  for _,rawRange:=range ranges{
   parts:=strings.Split(rawRange,"-");if len(parts)!=2{continue}
   low,e1:=strconv.ParseUint(parts[0],10,32);high,e2:=strconv.ParseUint(parts[1],10,32)
   if e1!=nil||e2!=nil||uint64(asn)<low||uint64(asn)>high{continue}
   for _,rawURL:=range urls{u,err:=url.Parse(strings.TrimSpace(rawURL));if err==nil&&u.Scheme=="https"&&u.Host!=""{return strings.TrimRight(u.String(),"/")+"/",nil}}
  }
 }
 return "",fmt.Errorf("IANA ASN RDAP bootstrap has no HTTPS service for AS%d",asn)
}

func sortUint32(values []uint32){for i:=1;i<len(values);i++{for j:=i;j>0&&values[j]<values[j-1];j--{values[j],values[j-1]=values[j-1],values[j]}}}

 
func RegisterASNReport(registry *evidence.Registry, report ASNReport)(bool,error){
 if registry==nil{return false,fmt.Errorf("evidence registry is required")}
 ip:=net.ParseIP(strings.TrimSpace(report.Target));if ip==nil{return false,fmt.Errorf("ASN report target is invalid")}
 if report.RetrievedAt.IsZero(){return false,fmt.Errorf("ASN retrieval timestamp is required")}
 if len(report.Records)==0{return false,fmt.Errorf("ASN report has no origin records")}
 details:=evidence.ASNOriginDetails{Target:ip.String()}
 records:=append([]ASNRecord(nil),report.Records...)
 sortASNRecords(records)
 for _,record:=range records{
  if record.ASN==0{return false,fmt.Errorf("ASN must be positive")}
  _,prefix,err:=net.ParseCIDR(record.Prefix);if err!=nil||!prefix.Contains(ip){return false,fmt.Errorf("ASN prefix %q does not contain target IP",record.Prefix)}
  if strings.TrimSpace(record.MappingSource)==""||strings.TrimSpace(record.RDAPSource)==""{return false,fmt.Errorf("ASN source attribution is required")}
  details.Records=append(details.Records,evidence.ASNOriginRecord{ASN:record.ASN,Prefix:prefix.String(),Country:strings.TrimSpace(record.Country),Registry:strings.TrimSpace(record.Registry),Allocated:strings.TrimSpace(record.Allocated),NetworkName:strings.TrimSpace(record.NetworkName),MappingSource:strings.TrimSpace(record.MappingSource),RDAPSource:strings.TrimSpace(record.RDAPSource)})
 }
 value,err:=json.Marshal(details);if err!=nil{return false,fmt.Errorf("encode ASN evidence: %w",err)}
 sum:=sha256.Sum256(value);key:=hex.EncodeToString(sum[:])
 item:=evidence.Evidence{ID:"asn-origin:"+key,EntityID:ip.String(),Type:evidence.TypeASNOrigin,Value:string(value)}
 if err:=registry.AddEvidence(item);err!=nil&&!errors.Is(err,evidence.ErrEvidenceExists){return false,fmt.Errorf("register ASN evidence: %w",err)}
 eventID:="asn-origin:"+key+":"+fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
 observation:=evidence.Observation{ID:"observation:"+eventID,EvidenceID:item.ID,Source:"Team Cymru origin DNS; IANA RDAP",ObservedAt:report.RetrievedAt.UTC(),EventIDs:[]string{eventID}}
 if err:=registry.AddObservation(observation);err!=nil{if errors.Is(err,evidence.ErrObservationExists){return false,nil};return false,fmt.Errorf("register ASN observation: %w",err)}
 return true,nil
}

func sortASNRecords(records []ASNRecord){
 for i:=1;i<len(records);i++{for j:=i;j>0&&records[j].ASN<records[j-1].ASN;j--{records[j],records[j-1]=records[j-1],records[j]}}
}
