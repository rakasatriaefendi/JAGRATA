import net from 'node:net';
import {createHmac,timingSafeEqual} from 'node:crypto';
import {nonce} from './state.ts';
import {fail} from './platform.ts';

const digest=(key:string,text:string)=>createHmac('sha256',key).update(text).digest('hex');
const valid=(a:string,b:string)=>typeof a==='string'&&/^[a-f0-9]{64}$/.test(a)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
export function sign(key:string,data:any){const payload=JSON.stringify(data);return {payload,proof:digest(key,payload)}}
export function verify(key:string,wire:any){
    if(typeof wire?.payload!=='string'||wire.payload.length>8192||!valid(wire.proof,digest(key,wire.payload)))fail('Application process ownership proof failed; no process was stopped.');
    return JSON.parse(wire.payload);
}

export function connect(port:number,wire:any):Promise<any>{
    if(!Number.isInteger(port)||port<1||port>65535)return Promise.reject(Error('Invalid control endpoint'));
    return new Promise((resolve,reject)=>{const socket=net.connect({host:'127.0.0.1',port});let text='',done=false;
        const finish=(error?:Error,value?:any)=>{if(done)return;done=true;socket.destroy();error?reject(error):resolve(value)};
        const deadline=setTimeout(()=>finish(Error('Application control absolute deadline')),2000);socket.once('close',()=>clearTimeout(deadline));
        socket.setTimeout(2000,()=>finish(Error('Application control timeout')));socket.on('error',e=>finish(e));
        socket.on('connect',()=>socket.write(JSON.stringify(wire)+'\n'));
        socket.on('data',chunk=>{text+=String(chunk);if(text.length>10000)return finish(Error('Control response too large'));if(text.includes('\n')){try{finish(undefined,JSON.parse(text.split('\n')[0]))}catch{finish(Error('Invalid control response'))}}});
        socket.on('end',()=>{if(!done)finish(Error('Incomplete control response'))});
    });
}
export async function request(config:any,key:string,record:any,operation:'status'|'stop'){
    if(!record||record.rootHash!==config.rootHash||record.id!==config.id||!/^\d+$/.test(String(record.pid))||!Number.isSafeInteger(record.pid)||record.pid<1||!/^[a-f0-9]{48}$/.test(record.instance))fail('Invalid process ownership record. No process was stopped.');
    const challenge=nonce();const data={op:operation,id:config.id,rootHash:config.rootHash,instance:record.instance,challenge,at:Date.now()};
    const answer=verify(key,await connect(record.controlPort,sign(key,data)));
    if(answer.challenge!==challenge||answer.instance!==record.instance||answer.rootHash!==config.rootHash||answer.id!==config.id||answer.pid!==record.pid)fail('Process identity mismatch. No process was stopped.');
    return answer;
}

export async function serve(config:any,key:string,instance:string,read:()=>any,stop:()=>void){
    const challenges=new Map<string,number>();
    const server=net.createServer(socket=>{socket.setTimeout(2000,()=>socket.destroy());let text='',handled=false;
        socket.on('error',()=>{});socket.on('data',chunk=>{if(handled)return;text+=String(chunk);if(text.length>10000){socket.destroy();return}if(!text.includes('\n'))return;handled=true;
            try {
                const data=verify(key,JSON.parse(text.split('\n')[0]));const now=Date.now();
                for(const[k,time]of challenges)if(now-time>10000)challenges.delete(k);
                if(!['status','stop'].includes(data.op)||data.id!==config.id||data.rootHash!==config.rootHash||data.instance!==instance||typeof data.challenge!=='string'||!/^[a-f0-9]{48}$/.test(data.challenge)||!Number.isSafeInteger(data.at)||Math.abs(now-data.at)>5000||challenges.has(data.challenge)||challenges.size>=128)throw Error('Rejected control request');
                challenges.set(data.challenge,now);
                const response={...read(),challenge:data.challenge,instance,id:config.id,rootHash:config.rootHash,pid:process.pid};
                socket.end(JSON.stringify(sign(key,response))+'\n',()=>{if(data.op==='stop')stop()});
            } catch {socket.destroy()}
        });
    });
    server.maxConnections=16;
    await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>{server.removeListener('error',reject);resolve()})});
    return server;
}
