import { basicSetup } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { EditorView, keymap } from '@codemirror/view';
import { HighlightStyle, syntaxHighlighting, StreamLanguage } from '@codemirror/language';
import { tags } from '@lezer/highlight';
import { markdown } from '@codemirror/lang-markdown';
import { javascript } from '@codemirror/lang-javascript';
import { rust } from '@codemirror/lang-rust';
import { python } from '@codemirror/lang-python';
import { json } from '@codemirror/lang-json';
import { html } from '@codemirror/lang-html';
import { css } from '@codemirror/lang-css';
import { cpp } from '@codemirror/lang-cpp';
import { yaml } from '@codemirror/legacy-modes/mode/yaml';
import { toml } from '@codemirror/legacy-modes/mode/toml';
import { shell } from '@codemirror/legacy-modes/mode/shell';
import { O_CREAT, O_EXCL, O_TRUNC, O_WRONLY, call, pwrite, sys } from './http.mjs';
const $ = id => document.getElementById(id);
const theme = EditorView.theme({
 '&': { color: '#d0dbd3', backgroundColor: '#101614', height: '100%', fontSize: '20px' },
 '.cm-scroller': { fontFamily: 'inherit', lineHeight: '1.65' },
 '.cm-content': { caretColor: '#9ae6b5', padding: '16px 0' },
 '.cm-cursor, .cm-dropCursor': { borderLeftColor: '#9ae6b5' },
 '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: '#2b4835' },
 '.cm-activeLine': { backgroundColor: '#18241c' }, '.cm-activeLineGutter': { backgroundColor: '#18241c' },
 '.cm-gutters': { backgroundColor: '#0b100d', color: '#728779', border: 'none' },
 '.cm-panels': { backgroundColor: '#152019', color: '#d0dbd3' },
 '.cm-tooltip': { backgroundColor: '#152019', border: '1px solid #405448' },
}, { dark: true });
const highlight = HighlightStyle.define([
 { tag: [tags.keyword, tags.operator, tags.heading], color: '#9ae6b5' },
 { tag: [tags.string, tags.number, tags.bool], color: '#d8c395' },
 { tag: [tags.comment, tags.meta], color: '#7d9486', fontStyle: 'italic' },
 { tag: [tags.typeName, tags.function(tags.variableName)], color: '#c0ddc9' },
 { tag: tags.link, color: '#9ae6b5', textDecoration: 'underline' },
]);
function language(path) {
 const ext=path.split('.').pop().toLowerCase();
 if (ext==='md') return markdown();
 if (['js','jsx','ts','tsx'].includes(ext)) return javascript({typescript:ext.startsWith('t'),jsx:ext.endsWith('x')});
 if(ext==='rs')return rust(); if(ext==='py')return python(); if(['json','game'].includes(ext))return json();
 if(ext==='html')return html(); if(ext==='css')return css(); if(['c','h','cpp','hpp'].includes(ext))return cpp();
 if(['yaml','yml'].includes(ext))return StreamLanguage.define(yaml); if(ext==='toml')return StreamLanguage.define(toml); if(ext==='sh')return StreamLanguage.define(shell);
 return [];
}
let active;
export async function edit(path,{api,fileUrl,unlock,changed}) {
 if(active){active.view?.focus();return;}
 const dialog=$('editor'), body=$('editor-body'), status=$('editor-status'), save=$('editor-save'), discard=$('editor-discard');
 const state={path,view:null,dirty:false,saving:false,etag:null,existing:false,readOnly:false};active=state;
 $('editor-title').textContent=path; status.textContent='Loading...'; save.disabled=true; discard.hidden=true;
 body.replaceChildren();dialog.show();dialog.focus({preventScroll:true});
 const close=force=>{
  if(state.saving)return;
  if(state.dirty&&!force){status.textContent='You have unsaved changes. Save or choose Discard changes.';discard.hidden=false;return;}
  state.view?.destroy();active=null;dialog.close();body.replaceChildren();
 };
 const download=()=>{if(!state.view)return;const url=URL.createObjectURL(new Blob([state.view.state.doc.toString()],{type:'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=path.split('/').pop();a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 $('editor-close').onclick=()=>close(false);discard.onclick=()=>close(true);$('editor-download').onclick=download;
 dialog.oncancel=e=>{e.preventDefault();close(false);};
 const update=()=>{save.disabled=state.saving||state.readOnly||!state.view; $('editor-dirty').textContent=state.dirty?'Unsaved':'';};
 const saveDocument=async()=>{
  if(!state.view||state.saving||state.readOnly)return;
  const text=state.view.state.doc.toString();const bytes=new TextEncoder().encode(text);
  if(bytes.length>2_000_000){status.textContent='The editor can save up to 2 MB of text. Download your draft first.';return;}
  state.saving=true;update();
  try{
   const parent=path.slice(0,path.lastIndexOf('/'))||'/';
   if(!await unlock(parent))throw new Error('Save canceled');
   // Through a descriptor: a new file, or the one read replaced, if it is still the one read.
   let opened;
   try{opened=await call('open',state.existing?{path,flags:O_WRONLY|O_TRUNC,size:bytes.length,version:state.etag}:{path,flags:O_WRONLY|O_CREAT|O_EXCL,mode:0o666,size:bytes.length});}
   catch(error){throw new Error({ESTALE:'File changed in another session; reopen it or download your draft to avoid overwriting changes',EEXIST:'File was created by another session; reopen it',ENOENT:'File was deleted or moved; save it as a new file'}[error.errno]||error.message);}
   try{if(bytes.length)await pwrite(opened.fd,0,bytes);}
   catch(error){await sys([{close:{fd:opened.fd}}]);if(opened.created)await sys([{unlink:{path}}]);throw error;}
   const result=await call('close',{fd:opened.fd});state.etag=result.version;state.existing=true;
   // Edits may continue while the save request is in flight.
   state.dirty=state.view.state.doc.toString()!==text;
   status.textContent=state.dirty?'Submitted content saved; newer edits remain unsaved.':'Saved';discard.hidden=true;changed();
  }catch(error){status.textContent=error.message;}
  finally{state.saving=false;update();}
 };
 save.onclick=saveDocument;
 try{
  if(/\.(pdf|png|jpe?g|webp|gif|avif|bmp|ico|mp4|webm|mov|m4v|mp3|wav|ogg|m4a|flac)$/i.test(path))throw new Error('vim supports text, Markdown, and source files only');
  let text='';
  // What it is, and whether it may be written, as stat(2) and access(2) say; a new file if
  // there is none. One the account may not look at asks it to sign in.
  const look=()=>sys([{stat:{path}},{access:{path,mode:2}}]);
  let [found,writable]=await look();
  if(found.err?.errno==='EACCES'){if(!await unlock(path.slice(0,path.lastIndexOf('/'))||'/'))throw new Error('Permission denied');[found,writable]=await look();}
  if(found.err&&found.err.errno!=='ENOENT')throw new Error(found.err.detail||(found.err.errno==='EACCES'?'Permission denied':found.err.errno));
  const metadata=found.ok&&{directory:(found.ok.mode&0o170000)===0o040000,size:found.ok.size,writable:'ok' in writable};
  if(metadata){
   if(metadata.directory)throw new Error('This is a directory');
   if(metadata.size>2_000_000)throw new Error('File exceeds 2 MB; download it to edit locally');
   const response=await api(fileUrl(path));state.etag=response.headers.get('ETag');state.existing=true;state.readOnly=!metadata.writable;
   const bytes=await response.arrayBuffer();if(bytes.byteLength>2_000_000)throw new Error('File exceeds 2 MB');
   text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
   if(text.includes('\0'))throw new Error('The file contains binary data and cannot be edited as text');
  }
  if(active!==state)return;
  state.view=new EditorView({parent:body,state:EditorState.create({doc:text,extensions:[basicSetup,theme,syntaxHighlighting(highlight),language(path),EditorView.lineWrapping,
    EditorState.readOnly.of(state.readOnly),EditorView.editable.of(!state.readOnly),EditorView.contentAttributes.of({'aria-label':'File contents'}),
    keymap.of([{key:'Mod-s',run:()=>{void saveDocument();return true;}},{key:'Escape',run:()=>{close(false);return true;}}]),
    EditorView.updateListener.of(event=>{if(event.docChanged){state.dirty=true;update();}})]})});
  state.dirty=!state.existing;status.textContent=state.readOnly?'Read-only: your account does not have write permission':state.existing?'Ctrl / Cmd S to save; Esc to close':'New file: save to create it at this path';update();state.view.focus();
 }catch(error){if(active===state)status.textContent=error.message;}
}
window.addEventListener('beforeunload',event=>{if(active?.dirty){event.preventDefault();event.returnValue='';}});
