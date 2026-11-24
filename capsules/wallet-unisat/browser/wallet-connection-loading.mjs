// The loading surface works before the connector's larger module graph arrives.
document.addEventListener('click', event => {
  if (!event.target.closest('[data-connection-loading-cancel]')) return;
  const homeOrigin=new URLSearchParams(location.search).get('home_origin');
  const homeToken=new URLSearchParams(location.hash.slice(1)).get('home_token');
  try {
    if(window.top!==window&&homeToken&&new URL(homeOrigin).origin===homeOrigin&&/^https?:/.test(homeOrigin))
      window.top.postMessage({type:'home:close-self',homeToken},homeOrigin);
  }catch{}
});

// The connection window reports its content. Home owns and clamps outer bounds.
const container=document.querySelector('#connection-root, #wallet-window');
let fitFrame=0,lastFit='';
function reportContentSize() {
  fitFrame=0;
  const root=container?.querySelector('.connection-window');if(!root||window.top===window)return;
  const route=new URL(location.href),homeToken=new URLSearchParams(route.hash.slice(1)).get('home_token'),homeOrigin=route.searchParams.get('home_origin');
  if(!homeToken||!homeOrigin)return;
  try {if(new URL(homeOrigin).origin!==homeOrigin||!/^https?:/.test(homeOrigin))return;}catch{return;}
  const clone=root.cloneNode(true),width=Math.min(480,Math.max(280,Math.ceil(root.getBoundingClientRect().width)));
  Object.assign(clone.style,{position:'fixed',visibility:'hidden',pointerEvents:'none',width:width+'px',height:'auto',minHeight:'0',overflow:'visible'});
  document.body.append(clone);const height=Math.max(100,Math.min(4000,Math.ceil(clone.getBoundingClientRect().height)));clone.remove();
  const key=width+':'+height;if(lastFit===key)return;lastFit=key;
  window.top.postMessage({type:'home:wallet-content-size',homeToken,width,height},homeOrigin);
}
function scheduleContentFit(){if(!fitFrame)fitFrame=requestAnimationFrame(reportContentSize);}
const observer=container?new MutationObserver(scheduleContentFit):null;
observer?.observe(container,{childList:true,subtree:true,characterData:true});
addEventListener('resize',scheduleContentFit);
document.fonts?.ready.then(scheduleContentFit);scheduleContentFit();
addEventListener('pagehide',()=>{observer?.disconnect();cancelAnimationFrame(fitFrame);removeEventListener('resize',scheduleContentFit);},{once:true});
