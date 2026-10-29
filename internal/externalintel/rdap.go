package externalintel

import (
 "context"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "net/url"
 "sort"
 "strings"
 "time"

 "github.com/itsFuRy007/kem3t/internal/evidence"
)

const defaultRDAPBootstrapURL = "https://data.iana.org/rdap/dns.json"
const maxRDAPResponseBytes = 2 << 20

type RDAPEvent struct {
 Action string `json:"action"`
 Date string `json:"date"`
}

// RDAPReport intentionally excludes contact addresses, emails, phone numbers,
// and postal addresses; it keeps registration metadata useful for infrastructure research.
type RDAPReport struct {
 Target string `json:"target"`
 Source string `json:"source"`
 RetrievedAt time.Time `json:"retrieved_at"`
 Handle string `json:"handle,omitempty"`
 Registrar string `json:"registrar,omitempty"`
 Status []string `json:"status"`
 NameServers []string `json:"name_servers"`
 Events []RDAPEvent `json:"events"`
 Limitations []string `json:"limitations"`
}

type RDAPClient struct {
 HTTPClient *http.Client
 BootstrapURL string
 Timeout time.Duration
 Now func() time.Time
}

type rdapBootstrap struct { Services [][]json.RawMessage `json:"services"` }
type rdapDomainResponse struct {
 LDHName string `json:"ldhName"`
 Handle string `json:"handle"`
 Status []string `json:"status"`
 NameServers []struct { LDHName string `json:"ldhName"` } `json:"nameservers"`
 Events []struct { Action string `json:"eventAction"`; Date string `json:"eventDate"` } `json:"events"`
 Entities []struct { Roles []string `json:"roles"`; VCard []any `json:"vcardArray"` } `json:"entities"`
}

// LookupDomain discovers the authoritative RDAP service using IANA bootstrap data.
func (c *RDAPClient) LookupDomain(ctx context.Context, target string) (RDAPReport, error) {
 if ctx == nil { return RDAPReport{}, fmt.Errorf("context is required") }
 target = normalizeDomain(target)
 if !evidence.IsValidDomain(target) { return RDAPReport{}, fmt.Errorf("target must be a valid DNS domain") }
 timeout := c.Timeout; if timeout <= 0 { timeout = 12*time.Second }
 requestCtx, cancel := context.WithTimeout(ctx, timeout); defer cancel()
 client := c.HTTPClient
 if client == nil {
  client = &http.Client{Timeout:timeout, CheckRedirect:func(req *http.Request, via []*http.Request) error {
   if req.URL.Scheme != "https" { return fmt.Errorf("RDAP redirects must use HTTPS") }
   if len(via) >= 4 { return fmt.Errorf("too many RDAP redirects") }
   return nil
  }}
 }
 bootstrapURL := strings.TrimSpace(c.BootstrapURL); if bootstrapURL == "" { bootstrapURL = defaultRDAPBootstrapURL }
 bp, err := url.Parse(bootstrapURL)
 if err != nil || bp.Scheme != "https" || bp.Host == "" { return RDAPReport{}, fmt.Errorf("RDAP bootstrap URL must be an absolute HTTPS URL") }
 bootstrapBody, err := rdapGET(requestCtx, client, bootstrapURL)
 if err != nil { return RDAPReport{}, fmt.Errorf("fetch RDAP bootstrap: %w", err) }
 var bootstrap rdapBootstrap
 if err := json.Unmarshal(bootstrapBody, &bootstrap); err != nil { return RDAPReport{}, fmt.Errorf("decode RDAP bootstrap: %w", err) }
 serviceURL, err := selectRDAPService(bootstrap, target)
 if err != nil { return RDAPReport{}, err }
 service, err := url.Parse(serviceURL)
 if err != nil || service.Scheme != "https" || service.Host == "" { return RDAPReport{}, fmt.Errorf("RDAP bootstrap selected an invalid HTTPS service URL") }
 service.Path = strings.TrimRight(service.Path, "/") + "/domain/" + url.PathEscape(target)
 body, err := rdapGET(requestCtx, client, service.String())
 if err != nil { return RDAPReport{}, fmt.Errorf("query domain RDAP: %w", err) }
 var raw rdapDomainResponse
 if err := json.Unmarshal(body, &raw); err != nil { return RDAPReport{}, fmt.Errorf("decode domain RDAP response: %w", err) }
 if raw.LDHName != "" && normalizeDomain(raw.LDHName) != target { return RDAPReport{}, fmt.Errorf("RDAP response domain %q does not match requested target", raw.LDHName) }
 names := map[string]struct{}{}
 for _, ns := range raw.NameServers { name := normalizeDomain(ns.LDHName); if evidence.IsValidDomain(name) { names[name] = struct{}{} } }
 nameServers := make([]string, 0, len(names)); for name := range names { nameServers = append(nameServers,name) }; sort.Strings(nameServers)
 events := make([]RDAPEvent,0,len(raw.Events))
 for _, event := range raw.Events { action,date := strings.TrimSpace(event.Action),strings.TrimSpace(event.Date); if action!="" && date!="" { events=append(events,RDAPEvent{Action:action,Date:date}) } }
 sort.Slice(events,func(i,j int) bool { if events[i].Action!=events[j].Action{return events[i].Action<events[j].Action};return events[i].Date<events[j].Date })
 registrar := ""
 for _, entity := range raw.Entities {
  match:=false; for _, role := range entity.Roles { if strings.EqualFold(role,"registrar") { match=true;break } }
  if match { registrar=rdapRegistrarLabel(entity.VCard); if registrar!="" { break } }
 }
 now:=time.Now().UTC(); if c.Now!=nil { now=c.Now().UTC() }
 return RDAPReport{Target:target,Source:service.Host,RetrievedAt:now,Handle:strings.TrimSpace(raw.Handle),Registrar:registrar,Status:uniqueSorted(raw.Status),NameServers:nameServers,Events:events,Limitations:[]string{
  "RDAP data is registry-reported metadata and may be incomplete, delayed, redacted, or privacy-protected.",
  "A registrar label or nameserver does not independently prove who controls the infrastructure.",
  "Registration status is not a security verdict; a missing field does not prove the underlying fact does not exist.",
 }},nil
}

func rdapGET(ctx context.Context, client *http.Client, endpoint string) ([]byte,error) {
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil); if err!=nil{return nil,fmt.Errorf("create RDAP request: %w",err)}
 req.Header.Set("Accept","application/rdap+json, application/json"); req.Header.Set("User-Agent","KEM3T-External-Intelligence/1.0 (research)")
 resp,err:=client.Do(req); if err!=nil{return nil,err}; defer resp.Body.Close()
 if resp.StatusCode<200 || resp.StatusCode>=300 { _,_=io.Copy(io.Discard,io.LimitReader(resp.Body,2048));return nil,fmt.Errorf("HTTP %d",resp.StatusCode) }
 body,err:=io.ReadAll(io.LimitReader(resp.Body,maxRDAPResponseBytes+1));if err!=nil{return nil,err}
 if len(body)>maxRDAPResponseBytes{return nil,fmt.Errorf("response exceeds %d bytes",maxRDAPResponseBytes)}
 return body,nil
}

func selectRDAPService(bootstrap rdapBootstrap,target string)(string,error){
 labels:=strings.Split(target,".")
 for start:=0;start<len(labels);start++ {
  suffix:=strings.Join(labels[start:],"." )
  for _,service:=range bootstrap.Services {
   if len(service)!=2{continue};var suffixes,urls []string
   if json.Unmarshal(service[0],&suffixes)!=nil||json.Unmarshal(service[1],&urls)!=nil{continue}
   matched:=false;for _,candidate:=range suffixes{if strings.EqualFold(strings.TrimPrefix(candidate,"."),suffix){matched=true;break}}
   if !matched{continue}
   for _,rawURL:=range urls{parsed,err:=url.Parse(strings.TrimSpace(rawURL));if err==nil&&parsed.Scheme=="https"&&parsed.Host!=""{return strings.TrimRight(parsed.String(),"/")+"/",nil}}
  }
 }
 return "",fmt.Errorf("IANA RDAP bootstrap has no HTTPS service for %q",target)
}

func rdapRegistrarLabel(vcard []any)string{
 if len(vcard)<2{return ""};properties,ok:=vcard[1].([]any);if !ok{return ""}
 for _,item:=range properties{property,ok:=item.([]any);if !ok||len(property)<4{continue};key,_:=property[0].(string)
  if !strings.EqualFold(key,"org")&&!strings.EqualFold(key,"fn"){continue}
  switch value:=property[3].(type){case string:if strings.TrimSpace(value)!=""{return strings.TrimSpace(value)};case []any:for _,part:=range value{if s,ok:=part.(string);ok&&strings.TrimSpace(s)!=""{return strings.TrimSpace(s)}}}
 }
 return ""
}

func uniqueSorted(values []string)[]string{set:=map[string]struct{}{};for _,value:=range values{if value=strings.TrimSpace(value);value!=""{set[value]=struct{}{}}};result:=make([]string,0,len(set));for value:=range set{result=append(result,value)};sort.Strings(result);return result}
