import type { ARPBlockView, IsolationRequest } from "./types";

export interface ARPBlockEditor {
  view: ARPBlockView | null;
  selected: string;
  draft: IsolationRequest | null;
}

export const emptyARPBlockEditor: ARPBlockEditor = { view: null, selected: "", draft: null };

/** A refresh may update observations, but never replaces an unsaved choice. */
export function receiveARPBlockView(state: ARPBlockEditor, view: ARPBlockView): ARPBlockEditor {
  const selected = state.draft || view.segments.some(segment => segment.id === state.selected)
    ? state.selected
    : (view.segments.find(segment => segment.eligible) ?? view.segments[0])?.id ?? "";
  return { ...state, view, selected };
}

export function editARPBlockIsolation(state: ARPBlockEditor, enabled: boolean): ARPBlockEditor {
  const segment = state.view?.segments.find(item => item.id === state.selected);
  if (!state.view?.supported || !state.view.revision || !segment?.eligible) return state;
  // A new server revision must be reviewed explicitly, not adopted by toggling
  // an old draft after refresh.
  if (state.draft && state.draft.revision !== state.view.revision) return state;
  return {
    ...state,
    draft: segment.enabled === enabled ? null : { segment: segment.id, enabled, revision: state.view.revision },
  };
}

export function canApplyARPBlockIsolation(state: ARPBlockEditor): boolean {
  const segment = state.view?.segments.find(item => item.id === state.draft?.segment);
  return !!(state.view?.supported && state.draft?.revision && state.draft.revision === state.view.revision
    && segment?.eligible && segment.id === state.selected && segment.enabled !== state.draft.enabled);
}
