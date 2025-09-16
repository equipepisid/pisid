document.addEventListener('DOMContentLoaded',()=>{
  // Card stagger on load
  const cards=[...document.querySelectorAll('.info-card,.stat-card')];
  cards.forEach((c,i)=>{
    c.classList.add('reveal');
    setTimeout(()=>c.classList.add('show'), 100 + i*70);
  });

  // Scroll reveal for sections
  const observer=new IntersectionObserver((entries)=>{
    entries.forEach(e=>{
      if(e.isIntersecting){ e.target.classList.add('show'); }
    })
  },{threshold:0.12});

  document.querySelectorAll('.reveal, .checker-container, .steps .step').forEach(el=>{
    if(!el.classList.contains('reveal')) el.classList.add('reveal');
    observer.observe(el);
  });

  // Button press micro-interaction
  document.querySelectorAll('.btn').forEach(btn=>{
    btn.addEventListener('mousedown',()=>btn.style.transform='translateY(0) scale(0.98)');
    btn.addEventListener('mouseup',()=>btn.style.transform='');
    btn.addEventListener('mouseleave',()=>btn.style.transform='');
  });
});
