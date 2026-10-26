// Optional operator-injected status adapter. Not instantiated by the normal Manager.
// No registration, enrollment, sync, pull or preference-write command is permitted.
import {boundedText} from './security-read.ts';
import {sourceError} from './sources.ts';
const check=(ok:any,message:string)=>{if(!ok)throw sourceError(message,403)};
export function capiStatus(raw:string){check(raw.length<=65536&&raw.includes('You can successfully interact with Central API (CAPI)'),'Unrecognized or unsuccessful CAPI status response.');const subscription=raw.match(/^Subscription type: ([^\r\n]+)$/m)?.[1];return {authenticated:true,enrolled:raw.includes('Your instance is enrolled in the console'),subscriptionType:subscription?boundedText(subscription,64):null,reachability:'SUCCESSFUL_AT_OBSERVATION',sharing:raw.includes('Sharing signals is disabled')?false:raw.includes('Sharing signals is enabled')?true:null}}
export function papiStatus(raw:string){check(raw.length<=65536&&raw.includes('You can successfully interact with Polling API (PAPI)'),'Unrecognized or unsuccessful PAPI status response.');const plan=raw.match(/^Console plan: ([^\r\n]+)$/m)?.[1];check(plan,'Missing official plan response.');const subscriptions=[...raw.matchAll(/^ - ([a-zA-Z0-9_.-]+)\s*$/gm)].map(x=>x[1]);return {plan:boundedText(plan,64),categories:subscriptions,lastOrderReported:raw.match(/^Last order received: ([^\r\n]+)$/m)?.[1]?.slice(0,64)||null,categoryEligibility:(category:string)=>subscriptions.includes(category)}}
export class ApprovedExternalStatus{
 adapter:any;grant:any;clock:()=>number;cached:any=null;at=0;flight:Promise<any>|null=null;
 constructor(adapter:any,privateOperatorGrant:any,clock=Date.now){this.adapter=adapter;this.grant=privateOperatorGrant;this.clock=clock}
 snapshot(){if(this.flight)return this.flight;if(this.cached&&this.clock()-this.at<300000)return Promise.resolve(this.cached);this.flight=this.observe().then(v=>{this.at=this.clock();this.cached=v;return v}).finally(()=>this.flight=null);return this.flight}
 async observe(){
  const g=this.grant;check(g?.operation==='READ_EXTERNAL_STATUS'&&g.containerId===this.adapter.config.containerId&&typeof g.approvedBy==='string'&&g.approvedBy.length>0&&this.clock()<Date.parse(g.expiresAt),'Separate private external-network approval required.');
  const c=await this.adapter.owned();check(c.State.Running&&c.Image===g.imageId,'Approved engine/image mismatch.');const version=await this.adapter.call(['exec',c.Id,'cscli','version']);check(/^version: v1\.8\.1-[a-f0-9]{7,40}\s/m.test(version),'External status parser requires audited v1.8.1.');
  let capi:any=null,papi:any=null;const errors:string[]=[];
  try{capi=capiStatus(await this.adapter.call(['exec',c.Id,'cscli','capi','status']))}catch{errors.push('CAPI status unavailable; registration/eligibility not inferred.')}
  if(capi?.authenticated)try{const result=papiStatus(await this.adapter.call(['exec',c.Id,'cscli','papi','status']));const {categoryEligibility,...safe}=result;papi=safe}catch{errors.push('PAPI permissions unavailable; subscription not inferred.')}
  return {observedAt:new Date(this.clock()).toISOString(),state:errors.length?'PARTIAL':'AVAILABLE',capi,papi,errors,communityFeedEligibility:'UNKNOWN',networkApproval:g.approvedBy};
 }
}
