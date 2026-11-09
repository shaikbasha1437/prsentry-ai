// Intentionally buggy fixture used only to self-test the PRSentry action.
export function renderNote(el, note) {
  el.innerHTML = note.body;
  if (note.count == 0) console.log('empty note');
}
