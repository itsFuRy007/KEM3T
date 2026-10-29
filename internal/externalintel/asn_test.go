package externalintel

import (
 "context"
 "fmt"
 "net/http"
 "net/http/httptest"
 "net"
 "encoding/json"
 "testing"
 "time"
)

func TestASNLookupCombinesOriginMappingAndRDAP(t *testing.T){
 var server *httptest.Server
 server=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  switch r.URL.Path{
  case "/dns-query":
   if got:=r.URL.Query().Get("name");got!="8.8.8.8.origin.asn.cymru.com"{t.Errorf("query name=%q",got)}
   fmt.Fprint(w,"{\"Status\":0,\"Answer\":[{\"name\":\"origin.asn.cymru.com\",\"type\":16,\"data\":\"\\\"15169 | 8.8.8.0/24 | US | arin | 2000-03-30\\\"\"}]}")
  case "/asn-bootstrap":
   fmt.Fprintf(w,"{\"services\":[[[\"10000-20000\"],[%q]]]}",server.URL+"/rdap")
  case "/rdap/autnum/15169":
   fmt.Fprint(w,"{\"name\":\"GOOGLE\",\"handle\":\"AS15169\",\"startAutnum\":15169,\"endAutnum\":15169}")
  default:http.NotFound(w,r)
  }
 }))
 defer server.Close()
 client:=&ASNClient{HTTPClient:server.Client(),DNSOverHTTPS:server.URL+"/dns-query",BootstrapURL:server.URL+"/asn-bootstrap",Now:func()time.Time{return time.Date(2026,10,29,0,0,0,0,time.UTC)}}
 report,err:=client.LookupIP(context.Background(),"8.8.8.8");if err!=nil{t.Fatal(err)}
 if report.Target!="8.8.8.8"||len(report.Records)!=1{t.Fatalf("unexpected report: %+v",report)}
 record:=report.Records[0]
 if record.ASN!=15169||record.Prefix!="8.8.8.0/24"||record.Country!="US"||record.NetworkName!="GOOGLE"||record.RDAPSource==""{t.Fatalf("unexpected ASN record: %+v",record)}
}

func TestCymruOriginNameIPv4AndIPv6(t *testing.T){
 if got:=cymruOriginName(net.ParseIP("8.8.8.8"));got!="8.8.8.8.origin.asn.cymru.com"{t.Fatalf("IPv4 query=%q",got)}
 if got:=cymruOriginName(net.ParseIP("2001:4860:4860::8888"));got!="8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.1.0.0.2.origin6.asn.cymru.com"{t.Fatalf("IPv6 query=%q",got)}
}

func TestASNRejectsPrivateAndInvalidTargets(t *testing.T){
 client:=&ASNClient{}
 for _,target:=range []string{"", "example.com","192.168.1.1","127.0.0.1","fe80::1"}{
  if _,err:=client.LookupIP(context.Background(),target);err==nil{t.Fatalf("expected rejection for %q",target)}
 }
}

func TestSelectASNServiceFindsRange(t *testing.T){
 bootstrap:=asnBootstrap{Services:[][]json.RawMessage{
  {json.RawMessage(`["0-9999"]`),json.RawMessage(`["https://one.example/rdap"]`)},
  {json.RawMessage(`["10000-20000"]`),json.RawMessage(`["https://two.example/rdap"]`)},
 }}
 got,err:=selectASNService(bootstrap,15169);if err!=nil{t.Fatal(err)}
 if got!="https://two.example/rdap/"{t.Fatalf("service=%q",got)}
}
