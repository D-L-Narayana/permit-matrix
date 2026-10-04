import * as Dialog from '@radix-ui/react-dialog';

export interface ImportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  draft: string;
  onDraft: (text: string) => void;
  onFile: (file: File | undefined) => void;
  onReset: () => void;
  onValidate: () => void;
  errors: string[];
  /** Non-fatal importer notes (e.g. renamed path parameters, skipped operations). */
  notes?: string[];
  maxBytes: number;
  maxEndpoints: number;
  maxRoles: number;
  /**
   * id of the element that should regain focus when the dialog closes. The app opens this dialog from a plain
   * toolbar button rather than a Dialog.Trigger, so Radix has no trigger to return focus to and would leave it on <body>.
   */
  returnFocusId?: string;
}

const MAX_SHOWN_ERRORS = 12;

export function ImportDialog({ open, onOpenChange, draft, onDraft, onFile, onReset, onValidate, errors, notes, maxBytes, maxEndpoints, maxRoles, returnFocusId }: ImportDialogProps) {
  const onCloseAutoFocus = (event: Event) => {
    if (!returnFocusId) return;
    const target = document.getElementById(returnFocusId);
    if (target) {
      event.preventDefault(); // stops Radix from focusing its (absent) trigger
      target.focus();
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="dialog" aria-describedby="import-desc" onCloseAutoFocus={onCloseAutoFocus}>
          <Dialog.Title asChild><h2>Import a contract</h2></Dialog.Title>
          <Dialog.Description id="import-desc">
            Paste or choose a <code>permitmatrix.contract/1</code> JSON file (max {Math.round(maxBytes / 1024)} KB, {maxEndpoints} endpoints, {maxRoles} roles). OpenAPI 3.1 documents with <code>x-permitmatrix</code> extensions are also accepted. Servers must be <code>mock://</code> or localhost; anything else is refused. Use synthetic data only.
          </Dialog.Description>
          <label className="sr-only" htmlFor="contract-text">Contract JSON</label>
          <textarea id="contract-text" value={draft} onChange={(e) => onDraft(e.target.value)} spellCheck={false} />
          <div className="row">
            <label className="btn small" htmlFor="contract-file">
              Choose file…
              <input
                id="contract-file"
                type="file"
                accept="application/json,.json"
                className="sr-only"
                onChange={(e) => {
                  onFile(e.target.files?.[0]);
                  // Clear the selection so choosing the same file again (after fixing it) fires a change event.
                  e.target.value = '';
                }}
              />
            </label>
            <button className="btn small" onClick={onReset}>Reset to demo contract</button>
            <span className="spacer" />
            <Dialog.Close asChild><button className="btn small">Cancel</button></Dialog.Close>
            <button className="btn small primary" onClick={onValidate}>Validate and load</button>
          </div>
          {/* The live region is always present (empty until errors arrive) so assistive tech announces the list
              when it appears; putting role="alert" on the <ul> itself would orphan the list items. */}
          <div role="alert">
            {errors.length > 0 && (
              <ul className="errors">
                {errors.slice(0, MAX_SHOWN_ERRORS).map((e, i) => <li key={i}>{e}</li>)}
                {errors.length > MAX_SHOWN_ERRORS && <li>+{errors.length - MAX_SHOWN_ERRORS} more</li>}
              </ul>
            )}
          </div>
          {notes && notes.length > 0 && (
            <ul className="notes">{notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
