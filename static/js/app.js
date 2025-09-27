const lb = document.getElementById('logoutBtn');
if(lb){lb.addEventListener('click', async ()=>{const r = await fetch('/logout',{method:'POST'}); if(r.ok) location.href='/'})}
const burger = document.getElementById('burger');
if(burger){burger.addEventListener('click',()=>{document.body.classList.toggle('nav-open')})}

