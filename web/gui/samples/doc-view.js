// The document owns only its opaque frame and its private application channel.
const sheet = document.createElement('main');
const heading = document.createElement('h2');
heading.textContent = 'Notes';
const label = document.createElement('label');
label.textContent = 'Document text';
const editor = document.createElement('textarea');
editor.id = label.htmlFor = 'notes';
editor.rows = 5;
editor.cols = 30;
const count = document.createElement('output');
count.setAttribute('aria-live', 'polite');
const send = (action, fields) => {
  const error = window.gui.send(JSON.stringify({ action, ...fields }));
  if (error) count.textContent = error;
};
editor.addEventListener('input', () => send('edit', { text: editor.value }));
const actions = document.createElement('div');
const drag = document.createElement('button'); drag.textContent = 'Drag text';
drag.addEventListener('pointerdown', e => {
  if (e.button === 0) send('drag', { text: editor.value });
});
actions.append(drag);
for (const [action, name] of [['copy','Copy'], ['pick','Choose file'], ['notify','Notify']]) {
  const button = document.createElement('button'); button.textContent = name;
  button.onclick = () => send(action, action === 'copy' ? { text: editor.value } : {});
  actions.append(button);
}
window.gui.onmessage = text => { count.textContent = text; };
sheet.append(heading, label, editor, actions, count);
document.body.append(sheet);
