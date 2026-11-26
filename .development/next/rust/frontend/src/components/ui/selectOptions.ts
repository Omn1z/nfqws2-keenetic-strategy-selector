import { Children, Fragment, isValidElement, type ReactNode, type SelectHTMLAttributes } from "react";

export interface SelectOption {
  kind: "option";
  key: string;
  value: string;
  label: string;
  disabled: boolean;
  hidden: boolean;
  selected: boolean;
}
export interface SelectGroup {
  kind: "group";
  key: string;
  label: string;
  options: SelectOption[];
}
export type SelectEntry = SelectOption | SelectGroup;
export type SelectValue = string | string[] | null;
type NativeValue = SelectHTMLAttributes<HTMLSelectElement>["value"];

function optionText(node: ReactNode): string {
  let result = "";
  Children.forEach(node, (child) => {
    if (typeof child === "string" || typeof child === "number") result += child;
    else if (isValidElement<{ children?: ReactNode }>(child)) result += optionText(child.props.children);
  });
  return result.replace(/\s+/g, " ").trim();
}

/** Read native-style option children without serializing HTML. Arrays, fragments,
 * optgroups and numeric values preserve the behavior of the existing forms. */
export function readSelectOptions(children: ReactNode): { entries: SelectEntry[]; options: SelectOption[] } {
  let sequence = 0;
  function read(nodes: ReactNode, disabled = false): SelectEntry[] {
    const result: SelectEntry[] = [];
    Children.forEach(nodes, (child) => {
      if (!isValidElement<{ children?: ReactNode; value?: NativeValue; label?: string; disabled?: boolean; hidden?: boolean; selected?: boolean }>(child)) return;
      if (child.type === Fragment) { result.push(...read(child.props.children, disabled)); return; }
      const key = String(sequence++);
      if (child.type === "optgroup") {
        const nested = read(child.props.children, disabled || !!child.props.disabled);
        result.push({ kind: "group", key, label: child.props.label ?? "", options: nested.flatMap((entry) => entry.kind === "option" ? [entry] : entry.options) });
      } else if (child.type === "option") {
        const text = optionText(child.props.children);
        result.push({ kind: "option", key, value: child.props.value === undefined ? text : String(child.props.value), label: child.props.label || text,
          disabled: disabled || !!child.props.disabled, hidden: !!child.props.hidden, selected: !!child.props.selected });
      }
    });
    return result;
  }
  const entries = read(children);
  return { entries, options: entries.flatMap((entry) => entry.kind === "option" ? [entry] : entry.options) };
}

export function normalizeSelectValue(value: NativeValue | null, multiple: boolean): SelectValue {
  if (multiple) return value == null ? [] : (Array.isArray(value) ? value : [value]).map(String);
  if (value == null) return null;
  return String(Array.isArray(value) ? value[0] ?? "" : value);
}

export function initialSelectValue(value: NativeValue, options: SelectOption[], multiple: boolean): SelectValue {
  if (value !== undefined) return normalizeSelectValue(value, multiple);
  const selected = options.filter((option) => option.selected);
  if (multiple) return selected.map((option) => option.value);
  return (selected.at(-1) ?? options.find((option) => !option.disabled))?.value ?? null;
}
