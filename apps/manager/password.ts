// Local terminal or bounded automation stdin. Never echoed or put in arguments.
export async function passwordInput(){
    if(!process.stdin.isTTY){let text='';for await(const chunk of process.stdin){text+=chunk.toString();if(text.length>258)throw Error('Password too long')}return text.replace(/\r?\n$/,'')}
    process.stderr.write('New administrator password (14–256 characters; hidden): ');
    process.stdin.setRawMode(true);process.stdin.setEncoding('utf8');process.stdin.resume();
    return new Promise<string>((resolve,reject)=>{
        let text='';
        const finish=(error?:Error)=>{process.stdin.setRawMode(false);process.stdin.pause();process.stdin.removeListener('data',read);process.stderr.write('\n');error?reject(error):resolve(text)};
        const read=(chunk:string)=>{for(const c of chunk){
            if(c==='\u0003')return finish(Error('Cancelled'));
            if(c==='\r'||c==='\n')return finish();
            if(c==='\u007f'||c==='\b'){text=Array.from(text).slice(0,-1).join('');continue}
            if(c>=' ')text+=c;if(text.length>256)return finish(Error('Password too long'));
        }};
        process.stdin.on('data',read);
    });
}
