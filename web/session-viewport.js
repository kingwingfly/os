// Keep host applications inside the visible viewport when a mobile keyboard opens.
if (window.visualViewport) {
  const fit = () => {
    document.documentElement.style.setProperty('--session-height', `${visualViewport.height}px`);
    document.documentElement.style.setProperty('--session-top', `${visualViewport.offsetTop}px`);
  };
  visualViewport.addEventListener('resize', fit);
  visualViewport.addEventListener('scroll', fit);
  fit();
}
