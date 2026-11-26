// Observe transient product feedback before the action that produces it.
export async function observeCopiedFeedback(frame,selector){
 const observation=await frame.evaluateHandle(selector=>{
  const state={seen:false};
  const observer=new MutationObserver(()=>{
   const button=document.querySelector(selector);
   if(button?.textContent==='Copied'||button?.getAttribute('title')==='Copied'&&button?.getAttribute('aria-label')==='Copied'){
    state.seen=true;observer.disconnect();
   }
  });
  observer.observe(document,{subtree:true,attributes:true,childList:true,characterData:true,attributeFilter:['title','aria-label']});
  return {state,stop:()=>observer.disconnect()};
 },selector);
 return {
  wait:(timeout=5000)=>frame.waitForFunction(observation=>observation.state.seen,observation,{timeout}),
  close:async()=>{try{await observation.evaluate(observation=>observation.stop());}finally{await observation.dispose();}},
 };
}
