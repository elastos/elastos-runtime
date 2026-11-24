import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const design=JSON.parse(readFileSync(new URL('../fixtures/wallet-connection-approval-stages.json',import.meta.url)));


// Independent acceptance IDs from Main's approving-action rule, not renderer flags.
export const approvalIds=['send-request','connect','restore-access','send-message','finish'];
export async function observeApproval(page){
 return page.evaluate(ids=>{
  const root=document.querySelector('main'),site=root.querySelector('.connection-site');
  const rect=e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};
  const nodes=[],walker=document.createTreeWalker(site,NodeFilter.SHOW_TEXT);while(walker.nextNode())nodes.push(walker.currentNode);
  const chars=[];for(const node of nodes)for(let i=0;i<node.length;i++){const range=document.createRange();range.setStart(node,i);range.setEnd(node,i+1);const box=range.getBoundingClientRect();if(box.width)chars.push({text:node.textContent[i],fontSize:parseFloat(getComputedStyle(node.parentElement).fontSize),color:getComputedStyle(node.parentElement).color,...rect({getBoundingClientRect:()=>box})});}
  const lastTop=chars.at(-1)?.top,last=chars.filter(c=>Math.abs(c.top-lastTop)<1);
  const end={left:Math.min(...last.map(c=>c.left)),right:Math.max(...last.map(c=>c.right)),top:Math.min(...last.map(c=>c.top)),bottom:Math.max(...last.map(c=>c.bottom))};
  const lines=[];for(const c of chars){let line=lines.find(l=>Math.abs(l.top-c.top)<1);if(!line){line={left:c.left,right:c.right,top:c.top,bottom:c.bottom,text:''};lines.push(line);}line.left=Math.min(line.left,c.left);line.right=Math.max(line.right,c.right);line.bottom=Math.max(line.bottom,c.bottom);line.text+=c.text;}
  const rgba=color=>{const values=color.match(/[\d.]+/g).map(Number);return values.length===3?[...values,1]:values;};
  const over=(a,b)=>[...a.slice(0,3).map((n,i)=>n*a[3]+b[i]*(1-a[3])),1];
  let ancestors=[],node=site;while(node){ancestors.unshift(node);node=node.parentElement;}let background=[255,255,255,1],opacity=1;for(const e of ancestors){background=over(rgba(getComputedStyle(e).backgroundColor),background);opacity*=Number(getComputedStyle(e).opacity);}
  const light=c=>{const s=c/255;return s<=.04045?s/12.92:((s+.055)/1.055)**2.4;};
  const luminance=c=>c.slice(0,3).reduce((sum,n,i)=>sum+light(n)*[.2126,.7152,.0722][i],0);
  const contrasts=chars.map(c=>{const fg=rgba(c.color);fg[3]*=opacity;const a=luminance(over(fg,background)),b=luminance(background);return(Math.max(a,b)+.05)/(Math.min(a,b)+.05);});
  const controls=[...root.querySelectorAll('button')].filter(b=>ids.includes(b.dataset.action)).map(b=>({id:b.dataset.action,position:getComputedStyle(b).position,parentPosition:getComputedStyle(b.parentElement).position,...rect(b)}));
  const intersects=b=>b.bottom>0&&b.top<innerHeight&&b.right>0&&b.left<innerWidth;
  const unit=site.closest('.connection-approval-unit');
  const canvas=document.createElement('canvas'),ctx=canvas.getContext('2d'),style=getComputedStyle(site);ctx.font=style.fontWeight+' '+style.fontSize+' '+style.fontFamily;
  const origin=site.textContent,authority=origin.slice(origin.indexOf('://')+3),tail=authority.split('.').slice(-3).join('.');
  let offset=origin.indexOf('://')+3,labelsIntact=true;const hostLabels=authority.split('.');for(const [index,label]of hostLabels.entries()){const boxes=chars.slice(offset,offset+label.length);if(ctx.measureText(label+(index<hostLabels.length-1?'.':'')).width<=site.parentElement.clientWidth-1&&boxes.some(c=>Math.abs(c.top-boxes[0].top)>1))labelsIntact=false;offset+=label.length+1;}
  return {lines,minFontSize:Math.min(...chars.map(c=>c.fontSize)),minGlyphHeight:Math.min(...chars.map(c=>c.height)),contrast:Math.min(...contrasts),labelsIntact,tailFits:ctx.measureText(tail).width<=site.parentElement.clientWidth-1,tail,origin:site.textContent,lastText:last.map(c=>c.text).join(''),end,controls,visible:controls.filter(intersects),width:innerWidth,height:innerHeight,scrollTop:root.scrollTop,maxScroll:root.scrollHeight-root.clientHeight,structure:!!unit&&unit.firstElementChild?.contains(site)&&unit.lastElementChild?.classList.contains('connection-approve-actions')&&unit.children.length===2&&unit.firstElementChild===site.parentElement&&site.parentElement.lastElementChild===site&&[...site.parentElement.children].every(e=>e===site||e.tagName==='SPAN'&&e.textContent==='Site in Browser')&&unit.closest('article')?.lastElementChild===unit,rootOverflow:getComputedStyle(root).overflowY,completeCharacters:chars.length===site.textContent.length,horizontal:chars.some(c=>c.left<-.5||c.right>innerWidth+.5),siteStyle:{clipPath:getComputedStyle(site).clipPath,opacity:getComputedStyle(site).opacity,overflow:getComputedStyle(site).overflow,whiteSpace:getComputedStyle(site).whiteSpace,textOverflow:getComputedStyle(site).textOverflow},topExit:!!root.querySelector('.connection-card-start [data-action="close-window"]'),cue:root.querySelector('.connection-more')?.textContent,siteRect:rect(site)};
 },approvalIds);
}
export function assertApprovalGeometry(o){
 assert(o.minFontSize>=design.minimumSiteFontPx,'site font must retain the design 13px minimum');
 assert(o.minGlyphHeight>=design.minimumSiteFontPx,'site glyphs must retain the design rendered size');
 assert(o.contrast>=design.minimumContrast,'site contrast must be at least 4.5:1 against the card');
 assert(o.completeCharacters,'every origin character has layout');
 assert(!o.horizontal,'every origin character wraps inside the viewport');
 assert(o.structure,'O4: site must immediately precede approving controls at the card end');
 assert(o.labelsIntact,'a fitting label must never break at a hyphen');if(o.tailFits)assert(o.lastText.endsWith(o.tail),'last three labels and port stay together when they fit');
 for(const b of o.controls)assert(!['fixed','absolute','sticky'].includes(b.position)&&!['fixed','absolute','sticky'].includes(b.parentPosition),'approving controls stay in site flow');
 assert.equal(o.siteStyle.whiteSpace,'normal');assert.notEqual(o.siteStyle.textOverflow,'ellipsis','ellipsis');
 for(const b of o.visible){
  assert(o.end.top>=-0.5&&o.end.bottom<=o.height+0.5,'final site line must be fully visible whenever approval intersects');
  assert(b.top>=o.end.bottom-0.5&&b.top-o.end.bottom<=design.maximumDecisionGapPx,'site final line must directly precede approval');
 }
}

// A label and its trailing dot form one non-leading-dot unit. The fit oracle
// measures that complete unit, including the dot at the 200% fallback-font edge.
// Compare the actual final-line pixels with a standalone reference, at exactly
// the same subpixel position. The reference excludes clipping, opacity and overlays.
export async function assertApprovalPaint(page,o,{captureFailure=true,line=null}={}){
 if(line)o={...o,end:line};else if(!o.visible.length)return;
 const x=Math.max(0,Math.floor(o.end.left)),y=Math.max(0,Math.floor(o.end.top)-1);
 const clip={x,y,width:Math.min(o.width-x,Math.ceil(o.end.right)-x+1),height:Math.min(o.height-y,Math.ceil(o.end.bottom)-y+1)};
 const dy=clip.y>=clip.height+2?-clip.height-2:clip.height+2;
 const pairedClip={x:clip.x,y:Math.min(clip.y,clip.y+dy),width:clip.width,height:clip.height*2+2};
 await page.evaluate(({clip,dy})=>{
  const site=document.querySelector('.connection-site'),row=site.parentElement,unit=site.closest('.connection-approval-unit');
  const box=row.getBoundingClientRect(),unitBox=unit.getBoundingClientRect();
  let parent=site,background='';while(parent){const color=getComputedStyle(parent).backgroundColor;if(color!=='rgba(0, 0, 0, 0)'&&color!=='transparent'){background=color;break;}parent=parent.parentElement;}
  const reference=document.createElement('div');reference.id='approval-paint-reference';
  window.__approvalUnitPosition=unit.style.position;unit.style.position='relative';
  // Capture the whole glyph rectangle, including font overhang outside the row.
  // The inner clone keeps the original row width and wrapping.
  reference.style.cssText=`position:absolute;left:${clip.x-unitBox.left}px;top:${clip.y+dy-unitBox.top}px;width:${clip.width}px;height:${clip.height}px;background:${background};overflow:hidden;z-index:2147483647;pointer-events:none;`;
  const clone=row.cloneNode(true),original=[row,...row.querySelectorAll('*')],copies=[clone,...clone.querySelectorAll('*')];
  const properties=['fontFamily','fontSize','fontWeight','fontStyle','lineHeight','letterSpacing','whiteSpace','wordBreak','overflowWrap','verticalAlign','unicodeBidi','direction','boxSizing','display','alignItems'];
  original.forEach((node,i)=>{const computed=getComputedStyle(node);copies[i].removeAttribute('class');copies[i].removeAttribute('style');for(const key of properties)copies[i].style[key]=computed[key];copies[i].style.color=computed.color;copies[i].style.opacity='1';copies[i].style.visibility='visible';copies[i].style.clipPath='none';copies[i].style.overflow='visible';if(['inline-grid','inline-block'].includes(computed.display)){copies[i].style.gridTemplateColumns='minmax(0,1fr)';copies[i].style.width='max-content';copies[i].style.maxWidth='100%';}});
  clone.style.cssText+=`;position:relative;left:${box.left-clip.x}px;top:${box.top-clip.y}px;width:${box.width}px;height:auto;margin:0;background:${background};`;
  reference.append(clone);unit.append(reference);
 },{clip,dy});
 let paired;
 try{paired=await page.screenshot({clip:pairedClip,animations:'disabled'});}finally{await page.evaluate(()=>{const reference=document.querySelector('#approval-paint-reference'),unit=reference.parentElement;reference.remove();unit.style.position=window.__approvalUnitPosition;delete window.__approvalUnitPosition;});}
 const pixels=await page.evaluate(async({paired,clip,pairedClip,dy})=>{
  const img=new Image();img.src='data:image/png;base64,'+paired;await img.decode();const canvas=document.createElement('canvas');canvas.width=img.width;canvas.height=img.height;const c=canvas.getContext('2d');c.drawImage(img,0,0);
  const scale=img.width/clip.width,width=img.width,height=Math.round(clip.height*scale);
  const a=c.getImageData(0,Math.round((clip.y-pairedClip.y)*scale),width,height).data,b=c.getImageData(0,Math.round((clip.y+dy-pairedClip.y)*scale),width,height).data;
  let changed=0,ink=0,actualInk=0,maxChannelDelta=0;const background=[...b.slice(0,3)];
  for(let i=0;i<a.length;i+=4){const delta=Math.max(...[0,1,2].map(k=>Math.abs(a[i+k]-b[i+k])));maxChannelDelta=Math.max(maxChannelDelta,delta);if(delta>0)changed++;if([0,1,2].some(k=>Math.abs(b[i+k]-background[k])>2))ink++;if([0,1,2].some(k=>Math.abs(a[i+k]-background[k])>2))actualInk++;}
  return {sameSize:a.length===b.length,changed,ink,actualInk,maxChannelDelta};
 },{paired:paired.toString('base64'),clip,pairedClip,dy});
 assert(pixels.sameSize&&pixels.ink>0&&pixels.actualInk>0,'standalone site line must contain glyph pixels');
 if(pixels.changed&&captureFailure&&process.env.WALLET_VIEW_PROOF_DIR){const {writeFile}=await import('node:fs/promises');const prefix=process.env.WALLET_VIEW_PROOF_DIR+'/paint-failure-'+page.context().browser().browserType().name();await writeFile(prefix+'-paired.png',paired);}
 // The sanitized reference shares the same scroll context and subpixel position; every RGB pixel must match.
 assert.equal(pixels.changed,0,'O2/opacity/overlay: site line must equal the standalone painted text');
 return {clip,...pixels};
}

/** Visit every origin line, including lines above a currently reachable action. */
export async function assertEverySiteLinePaint(page,{captureFailure=true}={}){
 const opening=await observeApproval(page),scroll=opening.scrollTop;let painted=0;
 try{for(const [index,line] of opening.lines.entries()){
   await page.evaluate(y=>{document.querySelector('main').scrollTop=y;},Math.max(0,scroll+line.top-2));
   const o=await observeApproval(page);assertApprovalGeometry(o);
   const visible=o.lines[index];
   assert(visible&&visible.text===line.text&&visible.top>=1&&visible.bottom<=o.height-1,'each indexed site line can be brought fully into view');
   await assertApprovalPaint(page,o,{captureFailure,line:visible});painted++;
 }}finally{await page.evaluate(y=>{document.querySelector('main').scrollTop=y;},scroll);}
 return painted;
}
