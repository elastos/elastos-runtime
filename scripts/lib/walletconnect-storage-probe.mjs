export function exerciseStorage() {
 const s=localStorage;const set=s.setItem,get=s.getItem,clear=s.clear,key=s.key;const error=fn=>{try{fn();return null;}catch(e){return e.name;}};
 clear.call(s);
 set.call(s,null,undefined);set.call(s,'choice',42);set.call(s,'choice',43);
 s.named=false;
 Object.defineProperty(s,'defined',{value:7,enumerable:true,writable:true,configurable:true});
 const symbol=Symbol('fixture');s[symbol]='symbol-value';
 const out={length:s.length,missing:get.call(s,'absent'),missingProperty:s.absent??null,nullKey:get.call(s,null),named:s.named,defined:s.defined,
   keys:Object.keys(s).sort(),keyNames:Array.from({length:s.length},(_,i)=>key.call(s,i)).sort(),negative:key.call(s,-1),overflow:key.call(s,2**32)===key.call(s,0),
   protoIdentity:Object.getPrototypeOf(s)===Storage.prototype,
   prototypeGet:error(()=>Storage.prototype.getItem.call(s,'choice')),
   tag:Object.prototype.toString.call(s),instance:s instanceof Storage,symbol:s[symbol],
   missingArgument:error(()=>get.call(s)),missingValue:error(()=>set.call(s,'only')),symbolValue:error(()=>set.call(s,'sym',Symbol())),
   bigintIndex:error(()=>key.call(s,1n)),badReceiver:error(()=>get.call({},'a'))};
 delete s.named;delete s[symbol];
 set.call(s,'getItem','reserved');set.call(s,'length','reserved');set.call(s,'__proto__','reserved');
 out.reserved={method:typeof s.getItem,length:s.length,proto:typeof s.__proto__,own:Object.keys(s).sort(),value:get.call(s,'getItem')};
 clear.call(s);out.empty=s.length;
 return out;
}
