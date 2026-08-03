"""Cross-platform inventory agent with one-time enrollment, mTLS heartbeat, and safe commands."""
from __future__ import annotations
import argparse,json,os,platform,socket,ssl,stat,subprocess,time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError,URLError
from urllib.request import Request,urlopen
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
AGENT_VERSION="0.2.0"; ALLOWED_COMMANDS=frozenset({"collect_inventory"})
def os_family()->str:return {"darwin":"macos","windows":"windows","linux":"linux"}.get(platform.system().lower(),"linux")
@dataclass(frozen=True)
class AgentConfig:
 api_base_url:str;state_dir:str;enrollment_key:str|None=None;heartbeat_seconds:int=60;inventory_every:int=60;request_timeout:int=30
 @classmethod
 def load(cls,path:Path)->"AgentConfig":
  raw=json.loads(path.read_text(encoding="utf-8"));return cls(str(raw["api_base_url"]).rstrip("/"),str(raw.get("state_dir","./agent-state")),os.environ.get("OPENINTEL_ENROLLMENT_KEY") or raw.get("enrollment_key"),max(15,int(raw.get("heartbeat_seconds",60))),max(1,int(raw.get("inventory_every",60))),max(5,int(raw.get("request_timeout",30))))
class AgentClient:
 def __init__(self,config:AgentConfig)->None:
  self.config=config;self.state=Path(config.state_dir).expanduser().resolve();self.state.mkdir(parents=True,exist_ok=True);self.key_path=self.state/"agent.key";self.cert_path=self.state/"agent.crt";self.ca_path=self.state/"ca.crt";self.identity_path=self.state/"identity.json";self.nonce_path=self.state/"seen-nonces.json"
 def _secret(self,path:Path,value:str)->None:
  path.write_text(value,encoding="utf-8")
  try:path.chmod(stat.S_IRUSR|stat.S_IWUSR)
  except OSError:pass
 def _request(self,method:str,path:str,payload:dict[str,Any]|None=None,enroll:bool=False)->dict:
  headers={"Accept":"application/json","User-Agent":f"openintel-agent/{AGENT_VERSION}"};context=ssl.create_default_context()
  if payload is not None:headers["Content-Type"]="application/json"
  if enroll:
   if not self.config.enrollment_key:raise RuntimeError("OPENINTEL_ENROLLMENT_KEY is required for first enrollment")
   headers["X-API-Key"]=self.config.enrollment_key
  else:context.load_verify_locations(cafile=str(self.ca_path));context.load_cert_chain(str(self.cert_path),str(self.key_path))
  request=Request(f"{self.config.api_base_url}{path}",data=json.dumps(payload).encode() if payload is not None else None,headers=headers,method=method)
  try:
   with urlopen(request,timeout=self.config.request_timeout,context=context) as response:return json.loads(response.read().decode())
  except HTTPError as exc:raise RuntimeError(f"API returned HTTP {exc.code}") from exc
  except URLError as exc:raise RuntimeError(f"API unreachable: {exc.reason}") from exc
 def enroll(self)->dict:
  if self.identity_path.exists():return json.loads(self.identity_path.read_text())
  key=rsa.generate_private_key(public_exponent=65537,key_size=3072);subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,socket.gethostname())]);csr=x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key,hashes.SHA256())
  result=self._request("POST","/agents/enroll",{"hostname":socket.gethostname(),"os_family":os_family(),"os_version":platform.platform(),"agent_version":AGENT_VERSION,"mac_address":None,"csr_pem":csr.public_bytes(serialization.Encoding.PEM).decode()},True)
  self._secret(self.key_path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode());self._secret(self.cert_path,result["certificate_pem"]);self.ca_path.write_text(result["ca_chain_pem"]);identity={k:result[k] for k in ("agent_id","asset_id","certificate_expires_at")};self.identity_path.write_text(json.dumps(identity,indent=2));return identity
 @staticmethod
 def _run(command:list[str])->list[str]:
  try:value=subprocess.run(command,capture_output=True,text=True,timeout=30,check=False);return value.stdout.splitlines() if value.returncode==0 else []
  except (OSError,subprocess.TimeoutExpired):return []
 def inventory(self)->list[dict[str,str|None]]:
  family=os_family();lines=[]
  if family=="linux":lines=self._run(["dpkg-query","-W","-f=${Package}\t${Version}\n"]) or self._run(["rpm","-qa","--qf","%{NAME}\t%{VERSION}-%{RELEASE}\n"])
  elif family=="windows":lines=self._run(["powershell","-NoProfile","-NonInteractive","-Command","Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object DisplayName | % { $_.DisplayName + \"`t\" + $_.DisplayVersion }"])
  else:
   raw="\n".join(self._run(["system_profiler","SPApplicationsDataType","-json"]))
   try:return [{"name":x.get("_name","unknown"),"version":x.get("version"),"vendor":None,"cpe_uri":None} for x in json.loads(raw).get("SPApplicationsDataType",[])][:10000]
   except json.JSONDecodeError:return []
  result=[]
  for line in lines:
   name,_,version=line.partition("\t")
   if name.strip():result.append({"name":name.strip(),"version":version.strip() or None,"vendor":None,"cpe_uri":None})
  return result[:10000]
 def heartbeat(self,inventory:bool)->dict:return self._request("POST","/agents/heartbeat",{"agent_version":AGENT_VERSION,"os_version":platform.platform(),"ip_address":None,"software":self.inventory() if inventory else None})
 def _seen(self)->set[str]:
  try:return set(json.loads(self.nonce_path.read_text()))
  except (FileNotFoundError,json.JSONDecodeError):return set()
 def poll_commands(self)->int:
  seen=self._seen();commands=self._request("GET","/agents/commands/poll").get("commands",[]);handled=0
  for command in commands:
   nonce=str(command.get("nonce", ""));command_id=str(command.get("id", ""));kind=str(command.get("command", ""))
   if not nonce or not command_id:continue
   if nonce in seen:self._request("POST",f"/agents/commands/{command_id}/ack",{"nonce":nonce,"state":"rejected","result":{"reason":"replay_detected"}});continue
   seen.add(nonce)
   if kind not in ALLOWED_COMMANDS:self._request("POST",f"/agents/commands/{command_id}/ack",{"nonce":nonce,"state":"rejected","result":{"reason":"command_not_allowlisted"}});continue
   try:self.heartbeat(True);state="completed";result={"inventory_submitted":True}
   except RuntimeError as exc:state="failed";result={"error":type(exc).__name__}
   self._request("POST",f"/agents/commands/{command_id}/ack",{"nonce":nonce,"state":state,"result":result});handled+=1
  self._secret(self.nonce_path,json.dumps(sorted(seen)[-10000:]));return handled
 def run(self)->None:
  self.enroll();count=0
  while True:
   try:response=self.heartbeat(count%self.config.inventory_every==0);self.poll_commands();delay=max(15,int(response.get("next_heartbeat_seconds",self.config.heartbeat_seconds)));count+=1
   except RuntimeError as exc:print(f"agent cycle failed: {exc}",flush=True);delay=min(300,self.config.heartbeat_seconds*2)
   time.sleep(delay)
def main()->None:
 parser=argparse.ArgumentParser();parser.add_argument("--config",type=Path,required=True);parser.add_argument("--once",action="store_true");args=parser.parse_args();client=AgentClient(AgentConfig.load(args.config));client.enroll()
 if args.once:print(json.dumps({"heartbeat":client.heartbeat(True),"commands":client.poll_commands()},indent=2,default=str))
 else:client.run()
if __name__=="__main__":main()
