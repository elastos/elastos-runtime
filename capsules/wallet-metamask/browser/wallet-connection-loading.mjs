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
