/* Vanilla DOM adapter for i18next. Text/attribute updates only: never replace forms,
 * re-render pages, assign translation HTML, alter input values or mutate API data.
 * UI-authored catalog messages are allowlisted. User/evidence regions are excluded.
 */
(()=>{
 'use strict';
 const api=window.i18next,resources=window.JAGRATA_LOCALES;
 const valid=language=>language==='en'||language==='id';
 const saved=(()=>{try{return localStorage.getItem('jagrata-language')}catch{return null}})();
 const missingKeys=new Set(),untranslated=new Set(),dates=new Map(),texts=new WeakMap(),attributes=new WeakMap();
 api.init({resources,lng:valid(saved)?saved:'en',supportedLngs:['en','id'],fallbackLng:'en',keySeparator:false,nsSeparator:false,initAsync:false,returnEmptyString:false,interpolation:{escapeValue:false},debug:false});
 const english=resources.en.translation,exact=new Map(Object.entries(english).map(([key,value])=>[value,key]));
 const patterns=Object.entries(english).filter(([,value])=>value.includes('{{')).map(([key,value])=>{let source='',at=0;const names=[];for(const match of value.matchAll(/{{(\w+)}}/g)){source+=value.slice(at,match.index).replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(.+?)';names.push(match[1]);at=match.index+match[0].length}source+=value.slice(at).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');return {key,names,regex:new RegExp('^'+source+'$')}});
 const fragments=[...exact.keys()].filter(s=>!s.includes('{{')&&s.length>=12).sort((a,b)=>b.length-a.length);
 const locale=()=>api.language==='id'?'id-ID':'en-US';
 const defaultZone='Asia/Jakarta';
 const validZone=value=>{try{return typeof value==='string'&&value.length<100&&!!new Intl.DateTimeFormat('en',{timeZone:value}).resolvedOptions().timeZone}catch{return false}};
 const storedZone=(()=>{try{return localStorage.getItem('jagrata-timezone')}catch{return null}})();
 let timeZone=validZone(storedZone)?storedZone:defaultZone;
 // Only explicit, offset-bearing instants have a source contract. Naive values stay raw.
 const instant=value=>typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d+)?)?(?:Z|[+-]\d\d:\d\d)$/.test(value)&&Number.isFinite(Date.parse(value));
 const dateOptions=zone=>({year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZone:zone,timeZoneName:'shortOffset'});
 const zoneOffset=(zone,date=new Date())=>new Intl.DateTimeFormat('en',{timeZone:zone,timeZoneName:'longOffset'}).formatToParts(date).find(p=>p.type==='timeZoneName').value.replace('GMT','UTC');
 const number=value=>new Intl.NumberFormat(locale(),{maximumFractionDigits:6}).format(Number(value));
 const translate=(key,values={})=>{if(!api.exists(key)){missingKeys.add(key);return english[key]||key}return api.t(key,values)};
 function baseDate(value,dateOnly=false){if(!instant(value))return String(value??'');const date=new Date(value);const en=new Intl.DateTimeFormat('en-US',dateOnly?{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'}:dateOptions('UTC')).format(date);dates.set(en,{date,dateOnly});return en}
 function localizedDate(record){return new Intl.DateTimeFormat(locale(),record.dateOnly?{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'}:dateOptions(timeZone)).format(record.date)}
 function changeZone(value){if(!validZone(value))return false;timeZone=value;try{localStorage.setItem('jagrata-timezone',value)}catch{}apply();document.dispatchEvent(new CustomEvent('jagrata:timezone',{detail:{timeZone}}));return true}
 const commonZones=['Asia/Jakarta','Asia/Makassar','Asia/Jayapura','Asia/Bangkok','Asia/Singapore','Asia/Tokyo','UTC','America/New_York','Europe/London'];
 const zones=[...new Set([...commonZones,...(Intl.supportedValuesOf?.('timeZone')||[])])];
 const zoneNames={'Asia/Jakarta':['Jakarta, Indonesia (WIB)','Jakarta, Indonesia (WIB)'],'Asia/Makassar':['Makassar, Indonesia (WITA)','Makassar, Indonesia (WITA)'],'Asia/Jayapura':['Jayapura, Indonesia (WIT)','Jayapura, Indonesia (WIT)'],'Asia/Bangkok':['Bangkok, Thailand','Bangkok, Thailand'],'Asia/Singapore':['Singapore','Singapura'],'Asia/Tokyo':['Tokyo, Japan','Tokyo, Jepang']};
 function fillZones(){const select=document.querySelector('#timezone-select');if(!select)return;const query=(document.querySelector('#timezone-search')?.value||'').toLowerCase();const previous=select.value;select.replaceChildren();for(const zone of zones){const label=zoneNames[zone]?.[api.language==='id'?1:0]||zone.replaceAll('_',' ');if(zone!==timeZone&&!`${zone} ${label}`.toLowerCase().includes(query))continue;const option=document.createElement('option');option.value=zone;option.textContent=`${zoneOffset(zone)} — ${label}`;option.setAttribute('data-immutable','');select.append(option)}select.value=zones.includes(previous)&&[...select.options].some(o=>o.value===previous)?previous:timeZone}
 document.querySelector('#timezone-search')?.addEventListener('input',fillZones);
 document.querySelector('#timezone-select')?.addEventListener('change',event=>changeZone(event.target.value));
 document.addEventListener('jagrata:language',fillZones);
 function message(source,depth=0){
  source=source.replaceAll('1â€“80','1–80');
  const key=exact.get(source);if(key&&!source.includes('{{'))return translate(key);
  if(depth<2)for(const pattern of patterns){const matched=source.match(pattern.regex);if(matched){const values={};pattern.names.forEach((name,i)=>{const value=matched[i+1];values[name]=['count','total','selected','page','reads','parsed','revision','number'].includes(name)&&/^\d+$/.test(value)?number(value):message(value,depth+1)});return translate(pattern.key,values)}}
  if(dates.has(source))return localizedDate(dates.get(source));
  // Composed, server-authored explanations are localized in bounded fragments.
  // Never invoke this on user-generated content, evidence, IDs or form values.
  let rest=source,result='';while(rest){let found=null,index=rest.length;for(const fragment of fragments){const pos=rest.indexOf(fragment);if(pos>=0&&pos<index){found=fragment;index=pos}}if(!found){result+=rest;break}result+=rest.slice(0,index)+translate(exact.get(found));rest=rest.slice(index+found.length)}
  for(const [formatted,record]of dates)if(result.includes(formatted))result=result.split(formatted).join(localizedDate(record));
  return result;
 }
 const excluded='script,style,pre,[data-immutable],.scenario,.mono,.row-title,.evidence-event dl,.audit-list summary';
 function protect(node){const parent=node.parentElement;if(!parent)return true;if(parent.closest(excluded))return true;if(parent.closest('code')&&!parent.closest('.metric-list'))return true;if(parent.closest('dd')&&!parent.closest('[data-security-copy]')&&!dates.has(node.data.trim())&&!dates.has(texts.get(node)?.source.trim()))return true;return false}
 function renderText(node){
  if(protect(node))return;const current=node.data;if(!current.trim())return;let record=texts.get(node);if(!record||record.last!==current)record={source:current,last:current};
  const leading=record.source.match(/^\s*/)[0],trailing=record.source.match(/\s*$/)[0],source=record.source.trim();let output;
  if(node.parentElement.closest('[data-number]')&&/^\d+(\.\d+)?$/.test(source))output=number(source);else output=message(source);
  record.last=leading+output+trailing;texts.set(node,record);if(current!==record.last)node.data=record.last;
  if(api.language==='id'&&output===source&&/[a-zA-Z]{3}/.test(source)&&!exact.has(source)&&!dates.has(source)&&!/^([A-Z_0-9]+|JAGRATA|Always Awake\.|EN|ID|[#\d.,: /-]+)$/.test(source))untranslated.add(source);
 }
 function renderAttributes(element){for(const name of ['aria-label','title','placeholder','data-label']){const current=element.getAttribute(name);if(!current)continue;let map=attributes.get(element);if(!map){map=new Map();attributes.set(element,map)}let record=map.get(name);if(!record||record.last!==current)record={source:current,last:current};record.last=message(record.source);map.set(name,record);if(current!==record.last)element.setAttribute(name,record.last)}}
 function picker(){const select=document.createElement('select');select.className='language-picker dialog-language';select.setAttribute('aria-label','Language');select.title='Language';for(const code of ['en','id']){const option=document.createElement('option');option.value=code;option.textContent=code.toUpperCase();select.append(option)}select.value=api.language;return select}
 function apply(root=document.body){
  if(!root)return;document.documentElement.lang=api.language;document.title=translate('brand.title');
  for(const dialog of document.querySelectorAll('dialog[open]')){const head=dialog.querySelector('.dialog-head');if(head&&!head.querySelector('.language-picker'))head.insertBefore(picker(),head.querySelector('button'));if(head&&dialog.id!=='timezone-dialog'&&!head.querySelector('.timezone-open')){const button=document.createElement('button');button.type='button';button.className='timezone-open';button.textContent='◷';button.setAttribute('aria-label','Timezone');button.title='Timezone';head.insertBefore(button,head.querySelector('[data-close]'))}}
  const base=root.nodeType===Node.TEXT_NODE?root.parentElement:root;if(!base||base.closest?.('script,style'))return;
  if(base.nodeType===Node.ELEMENT_NODE)renderAttributes(base);
  for(const element of base.querySelectorAll?.('[aria-label],[title],[placeholder],[data-label]')||[])if(!element.closest(excluded))renderAttributes(element);
  const walker=document.createTreeWalker(base,NodeFilter.SHOW_TEXT);let node;while((node=walker.nextNode()))renderText(node);
  for(const select of document.querySelectorAll('.language-picker'))select.value=api.language;
  const indicator=document.querySelector('#timezone-indicator');if(indicator){const text=zoneOffset(timeZone);if(indicator.textContent!==text)indicator.textContent=text;if(indicator.title!==timeZone)indicator.title=timeZone}
 }
 let changing=false;async function change(language){if(!valid(language)||changing)return;changing=true;try{await api.changeLanguage(language);try{localStorage.setItem('jagrata-language',language)}catch{}apply();for(const element of document.querySelectorAll('input,select,textarea'))if(element.validity.customError)element.setCustomValidity(translate(element.validity.valueMissing?'validation.required':'validation.invalid'));document.dispatchEvent(new CustomEvent('jagrata:language',{detail:{language}}))}finally{changing=false}}
 document.addEventListener('change',event=>{if(event.target.matches('.language-picker'))void change(event.target.value)});
 document.addEventListener('invalid',event=>{if(event.target.setCustomValidity)event.target.setCustomValidity(translate(event.target.validity.valueMissing?'validation.required':'validation.invalid'))},true);
 document.addEventListener('input',event=>event.target.setCustomValidity?.(''));
 let scheduled=false;const observer=new MutationObserver(records=>{if(scheduled)return;if(!records.some(r=>r.type!=='attributes'||r.attributeName!=='lang'))return;scheduled=true;queueMicrotask(()=>{scheduled=false;apply()})});
 observer.observe(document.body,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['aria-label','title','placeholder','data-label','open']});
 window.JagrataI18n={change,apply,number,date:baseDate,translate,locale,missingKeys,untranslated,changeZone,validZone,zoneOffset,fillZones,formatInstant:value=>instant(value)?localizedDate({date:new Date(value),dateOnly:false}):String(value??''),get timeZone(){return timeZone},get language(){return api.language},version:'26.5.10'};
 fillZones();apply();
})();
