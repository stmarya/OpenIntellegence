import { timingSafeEqual } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
const BASE_URL=process.env.API_BASE_URL; const SERVICE_KEY=process.env.API_SERVICE_KEY; const ACTION_TOKEN=process.env.CONSOLE_ACTION_TOKEN;
const ACTIONS:Record<string,{path:(id?:string)=>string}>={create_case:{path:()=>'/cases'},create_investigation:{path:()=>'/investigations'},create_alert_rule:{path:()=>'/alert-rules'},acknowledge_alert:{path:(id)=>`/alerts/${encodeURIComponent(id??'')}/acknowledge`},trigger_ingest:{path:(id)=>`/ingest/${encodeURIComponent(id??'')}/run`},generate_report:{path:()=>'/reports/generate'},create_endpoint_intent:{path:()=>'/endpoint-intents'},create_api_key:{path:()=>'/api-keys'}};
function authorised(presented:string|null):boolean{
  if(!presented||!ACTION_TOKEN)return false; const a=Buffer.from(presented); const b=Buffer.from(ACTION_TOKEN); return a.length===b.length&&timingSafeEqual(a,b);
}
export async function POST(request:NextRequest){
  if(!BASE_URL||!/^https?:\/\//.test(BASE_URL)||!SERVICE_KEY||!ACTION_TOKEN)return NextResponse.json({error:'Write gateway is disabled until API_BASE_URL, API_SERVICE_KEY, and CONSOLE_ACTION_TOKEN are configured.'},{status:503});
  if(!authorised(request.headers.get('X-Console-Action-Token')))return NextResponse.json({error:'Operator authorisation failed.'},{status:401});
  const origin=request.headers.get('origin'); if(origin&&origin!==request.nextUrl.origin)return NextResponse.json({error:'Cross-origin write requests are rejected.'},{status:403});
  let input:{action?:string;id?:string;payload?:unknown}; try{input=await request.json();}catch{return NextResponse.json({error:'Request body must be JSON.'},{status:400});}
  const operation=input.action?ACTIONS[input.action]:undefined; if(!operation)return NextResponse.json({error:'Action is not allowlisted.'},{status:422});
  if((input.action==='acknowledge_alert'||input.action==='trigger_ingest')&&!input.id)return NextResponse.json({error:'This action requires a target id.'},{status:422});
  try{const upstream=await fetch(`${BASE_URL}${operation.path(input.id)}`,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json','X-API-Key':SERVICE_KEY},body:JSON.stringify(input.payload??{}),cache:'no-store'}); const text=await upstream.text(); let body:unknown=null; try{body=text?JSON.parse(text):null;}catch{body={message:'Upstream returned non-JSON content.'};} return NextResponse.json(body,{status:upstream.status});}
  catch{return NextResponse.json({error:'The intelligence API could not be reached.'},{status:502});}
}
