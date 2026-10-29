package externalintel

import (
 "context"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "github.com/itsFuRy007/kem3t/internal/evidence"
 "github.com/itsFuRy007/kem3t/internal/graph"
)

func TestRDAPLookupUsesBootstrapAndNormalizesMetadata(t *testing.T) {
 var server *httptest.Server
 server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/rdap+json")
  switch {
  case r.URL.Path=="/bootstrap":
   fmt.Fprintf(w,"{\"services\":[[[\"com\"],[%q]]]}",server.URL+"/rdap")
  case r.URL.Path=="/rdap/domain/example.com":
   fmt.Fprint(w,"{\"ldhName\":\"EXAMPLE.COM\",\"handle\":\"EXAMPLE-123\",\"status\":[\"active\",\"active\",\"client transfer prohibited\"],\"nameservers\":[{\"ldhName\":\"NS1.EXAMPLE.COM.\"},{\"ldhName\":\"ns2.example.com\"},{\"ldhName\":\"ns1.example.com\"}],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"},{\"eventAction\":\"expiration\",\"eventDate\":\"2027-01-01T00:00:00Z\"}],\"entities\":[{\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"Example Registrar\"],[\"email\",{},\"text\",\"private@example.com\"]]]}]}")
  default: http.NotFound(w,r)
  }
 }))
 defer server.Close()
 client:=&RDAPClient{HTTPClient:server.Client(),BootstrapURL:server.URL+"/bootstrap",Now:func()time.Time{return time.Date(2026,10,29,0,0,0,0,time.UTC)}}
 report,err:=client.LookupDomain(context.Background(),"Example.COM.")
 if err!=nil{t.Fatal(err)}
 if report.Target!="example.com"||report.Handle!="EXAMPLE-123"{t.Fatalf("unexpected target/handle: %+v",report)}
 if report.Registrar!="Example Registrar"{t.Fatalf("registrar=%q",report.Registrar)}
 if strings.Join(report.Status,",")!="active,client transfer prohibited"{t.Fatalf("status=%v",report.Status)}
 if strings.Join(report.NameServers,",")!="ns1.example.com,ns2.example.com"{t.Fatalf("nameservers=%v",report.NameServers)}
 if len(report.Events)!=2||report.RetrievedAt.IsZero(){t.Fatalf("events/time missing: %+v",report)}
 encoded:=fmt.Sprintf("%+v",report)
 if strings.Contains(encoded,"private@example.com"){t.Fatal("RDAP contact email must not be collected")}
 if len(report.Limitations)<2{t.Fatal("expected interpretation limits")}
}

func TestRDAPRejectsInvalidTargetAndInsecureBootstrap(t *testing.T){
 for _,tc:=range []struct{target,bootstrap string}{{"192.0.2.1","https://data.iana.org/rdap/dns.json"},{"example.com","http://example.test/bootstrap"},{"","https://data.iana.org/rdap/dns.json"}}{
  client:=&RDAPClient{BootstrapURL:tc.bootstrap}
  if _,err:=client.LookupDomain(context.Background(),tc.target);err==nil{t.Fatalf("expected error for target=%q bootstrap=%q",tc.target,tc.bootstrap)}
 }
}

func TestRDAPRejectsMismatchedDomainResponse(t *testing.T){
 var server *httptest.Server
 server=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path=="/bootstrap"{fmt.Fprintf(w,"{\"services\":[[[\"com\"],[%q]]]}",server.URL+"/rdap");return}
  fmt.Fprint(w,"{\"ldhName\":\"not-example.com\",\"nameservers\":[]}")
 }))
 defer server.Close()
 client:=&RDAPClient{HTTPClient:server.Client(),BootstrapURL:server.URL+"/bootstrap"}
 if _,err:=client.LookupDomain(context.Background(),"example.com");err==nil{t.Fatal("expected target mismatch rejection")}
}

func TestRegisterRDAPReportPersistsProvenanceAndGraph(t *testing.T) {
 registry:=evidence.NewRegistry()
 report:=RDAPReport{Target:"example.com",Source:"rdap.example.test",RetrievedAt:time.Date(2026,10,29,12,0,0,0,time.UTC),Handle:"EXAMPLE-123",Registrar:"Example Registrar",Status:[]string{"active"},NameServers:[]string{"ns1.example.com","ns2.example.com"},Events:[]RDAPEvent{{Action:"registration",Date:"2020-01-01T00:00:00Z"}}}
 added,err:=RegisterRDAPReport(registry,report);if err!=nil{t.Fatal(err)};if !added{t.Fatal("expected first observation to be added")}
 g,err:=graph.BuildFromRegistry(registry);if err!=nil{t.Fatal(err)}
 if len(g.Nodes)!=4||len(g.Edges)!=3{t.Fatalf("unexpected graph size nodes=%d edges=%d",len(g.Nodes),len(g.Edges))}
 for _,edge:=range g.Edges{if len(edge.EvidenceIDs)==0||len(edge.ObservationIDs)==0{t.Fatalf("edge lacks provenance: %+v",edge)}}
 added,err=RegisterRDAPReport(registry,report);if err!=nil{t.Fatal(err)};if added{t.Fatal("duplicate timestamp should not add another observation")}
 report.RetrievedAt=report.RetrievedAt.Add(time.Hour)
 added,err=RegisterRDAPReport(registry,report);if err!=nil{t.Fatal(err)};if !added{t.Fatal("new retrieval time should be recorded as another observation")}
}

func TestRegisterRDAPReportRejectsInvalidNameserver(t *testing.T){
 registry:=evidence.NewRegistry()
 report:=RDAPReport{Target:"example.com",Source:"rdap.example.test",RetrievedAt:time.Now().UTC(),NameServers:[]string{"bad..name"}}
 if _,err:=RegisterRDAPReport(registry,report);err==nil{t.Fatal("expected invalid nameserver rejection")}
}
