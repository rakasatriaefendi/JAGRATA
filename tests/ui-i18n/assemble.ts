// Deterministic static asset synchronization, no compiler/bundler/build framework.
// Keeps the existing /client.js route operational in the already-running Manager.
import {readFile,writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
export async function bundle(){
 const en:any={},id:any={};for(const file of ['catalog','patterns','security','errors','security-ui'])for(const line of (await readFile(`apps/console/locales/${file}.tsv`,'utf8')).split(/\r?\n/).filter(Boolean)){const parts=line.split('\t');assert.equal(parts.length,3,'Expected key/EN/ID: '+line);const [key,english,indonesian]=parts;assert(!Object.hasOwn(en,key),'Duplicate key: '+key);assert(indonesian.trim());en[key]=english;id[key]=indonesian}
 const pkg=JSON.parse(await readFile('node_modules/i18next/package.json','utf8'));assert.equal(pkg.version,'26.5.10');
 const vendor=await readFile('node_modules/i18next/dist/umd/i18next.min.js','utf8');const license=await readFile('node_modules/i18next/LICENSE','utf8');
 const header='/* i18next 26.5.10, locally pinned browser distribution.\n'+license.replaceAll('*/','* /')+'\n*/\n';
 const resources={en:{translation:en},id:{translation:id}};
 const result=header+vendor+'\n;window.JAGRATA_LOCALES='+JSON.stringify(resources)+';\n'+await readFile('apps/console/i18n.js','utf8')+'\n/* JAGRATA application */\n'+await readFile('apps/console/ui.js','utf8')+'\n/* Security workspace */\n'+await readFile('apps/console/security-ui.js','utf8');
 return {result,en,id};
}
if(process.argv[1]?.replaceAll('\\','/').endsWith('/assemble.ts')){const {result,en,id}=await bundle();const css=await readFile('apps/console/responsive.css','utf8'),marker='/* JAGRATA responsive/localization overrides */';if(process.argv.includes('--check')){assert.equal(await readFile('apps/console/client.js','utf8'),result,'Static asset is out of sync');assert((await readFile('apps/console/styles.css','utf8')).endsWith(css),'CSS is out of sync')}else{await writeFile('apps/console/client.js',result);await writeFile('apps/console/locales/en.json',JSON.stringify(en,null,2)+'\n');await writeFile('apps/console/locales/id.json',JSON.stringify(id,null,2)+'\n');const base=(await readFile('apps/console/styles.css','utf8')).split(marker)[0];await writeFile('apps/console/styles.css',base+css)}console.log(JSON.stringify({keys:Object.keys(en).length,synchronized:true}))}
