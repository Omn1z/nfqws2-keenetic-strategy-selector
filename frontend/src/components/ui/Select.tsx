import { useEffect, useMemo, useRef, useState, type ButtonHTMLAttributes, type SelectHTMLAttributes } from "react";
import { Select as SelectPrimitive } from "@base-ui/react/select";
import { cn } from "@/lib/cn";
import { initialSelectValue, normalizeSelectValue, readSelectOptions, type SelectOption, type SelectValue } from "./selectOptions";

const triggerCls = "inline-flex w-full min-h-8 min-w-0 max-w-full items-center justify-between gap-2 rounded-md border border-transparent bg-rhea-input/50 px-2.5 py-1 text-left text-base leading-5 text-foreground outline-none transition-[color,box-shadow] duration-200 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm";
const itemCls = "relative flex min-h-8 w-full cursor-default items-center gap-2 rounded-sm py-1.5 pl-2 pr-8 text-sm outline-none select-none data-[highlighted]:bg-secondary data-[highlighted]:text-secondary-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50";

function Option({ option }: { option: SelectOption }) {
  if (option.hidden) return null;
  return <SelectPrimitive.Item data-slot="select-item" value={option.value} label={option.label} disabled={option.disabled} className={itemCls} title={option.label}>
    <SelectPrimitive.ItemText className="min-w-0 flex-1 whitespace-normal break-words [overflow-wrap:anywhere]">{option.label}</SelectPrimitive.ItemText>
    <SelectPrimitive.ItemIndicator className="pointer-events-none absolute right-2 flex size-4 items-center justify-center">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="size-4" aria-hidden="true"><path d="m5 12 4 4L19 6" /></svg>
    </SelectPrimitive.ItemIndicator>
  </SelectPrimitive.Item>;
}

/** Rhea/Neutral Select, retaining the project's native option/onChange API.
 * A hidden, noninteractive select supplies a real HTMLSelectElement event target
 * (value, selectedIndex and selectedOptions), never an OS popup or fake event.
 * Base UI owns keyboard navigation, typeahead, focus, portal and form validation. */
export function Select({ children, className, value, defaultValue, multiple = false, onChange, onInput, name, form, required, disabled, autoComplete, id, size: _size, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  const model = useMemo(() => readSelectOptions(children), [children]);
  const bridge = useRef<HTMLSelectElement>(null);
  const [open, setOpen] = useState(false);
  const [inheritedDisabled, setInheritedDisabled] = useState(false);
  const [local, setLocal] = useState<SelectValue | undefined>(() => defaultValue === undefined ? undefined : normalizeSelectValue(defaultValue, multiple));
  const initialDefault = useRef(defaultValue);
  const controlled = value !== undefined;
  const current = controlled ? normalizeSelectValue(value, multiple) : local === undefined ? initialSelectValue(undefined, model.options, multiple) : local;
  const items = useMemo(() => model.options.map((option) => ({ value: option.value, label: option.label })), [model]);
  const effectiveDisabled = disabled || inheritedDisabled;

  useEffect(() => {
    const element = bridge.current;
    if (!element) return;
    const sync = () => {
      const blocked = element.matches(":disabled");
      setInheritedDisabled(blocked);
      if (blocked) setOpen(false);
    };
    sync();
    // A portalled popup is outside its native fieldset. Track only ancestor
    // fieldsets' disabled attributes, so starting a save also closes an already
    // open menu. :disabled honors the first-legend exception automatically.
    const observer = new MutationObserver(sync);
    for (let ancestor = element.parentElement; ancestor; ancestor = ancestor.parentElement) {
      if (ancestor.tagName === "FIELDSET") observer.observe(ancestor, { attributes: true, attributeFilter: ["disabled"] });
    }
    return () => observer.disconnect();
  }, [disabled]);

  useEffect(() => {
    const owner = bridge.current?.form;
    if (!owner || controlled) return;
    const reset = () => setLocal(initialDefault.current === undefined ? undefined : normalizeSelectValue(initialDefault.current, multiple));
    owner.addEventListener("reset", reset);
    return () => owner.removeEventListener("reset", reset);
  }, [controlled, form, multiple]);

  const change = (next: SelectValue) => {
    if (effectiveDisabled || bridge.current?.matches(":disabled")) return;
    if (!controlled) setLocal(next);
    const element = bridge.current;
    if (!element) return;
    const selected = new Set(Array.isArray(next) ? next : next == null ? [] : [next]);
    for (const option of element.options) option.selected = selected.has(option.value);
    // React's native select change plugin supplies the existing callback with
    // the actual selection; controlled parents can accept or reject the change.
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  };

  return <>
    <SelectPrimitive.Root items={items} value={current} multiple={multiple} onValueChange={(next, details) => {
      if (effectiveDisabled || bridge.current?.matches(":disabled")) { details.cancel(); return; }
      change(next);
    }} open={open && !effectiveDisabled} onOpenChange={(next, details) => {
      if (next && (effectiveDisabled || bridge.current?.matches(":disabled"))) { details.cancel(); return; }
      setOpen(next);
    }} name={name} form={form} required={required} disabled={effectiveDisabled} autoComplete={autoComplete} id={id}>
      <SelectPrimitive.Trigger {...props as ButtonHTMLAttributes<HTMLButtonElement>} data-slot="select-trigger" className={cn(triggerCls, className)}>
        <SelectPrimitive.Value data-slot="select-value" className="min-w-0 flex-1 truncate" placeholder={model.options.find((option) => option.value === "")?.label ?? "Выберите…"} />
        <SelectPrimitive.Icon className="pointer-events-none ml-auto shrink-0 text-muted-foreground">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" className="size-4" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="m8 9 4-4 4 4m-8 6 4 4 4-4" /></svg>
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Positioner align="start" sideOffset={4} collisionPadding={8} alignItemWithTrigger={false} className="isolate z-[100]">
          <SelectPrimitive.Popup data-slot="select-content" className="relative isolate max-h-[min(var(--available-height),24rem)] w-[var(--anchor-width)] min-w-[min(10rem,calc(100vw-1rem))] max-w-[calc(100vw-1rem)] overflow-x-hidden overflow-y-auto rounded-md bg-popover text-popover-foreground shadow-lg ring-1 ring-foreground/10 outline-none dark:ring-foreground/15">
            <SelectPrimitive.ScrollUpArrow className="sticky top-0 z-10 flex h-6 items-center justify-center bg-popover text-muted-foreground" aria-hidden="true">⌃</SelectPrimitive.ScrollUpArrow>
            <SelectPrimitive.List className="p-1">
              {model.entries.map((entry) => entry.kind === "option" ? <Option key={entry.key} option={entry} /> : <SelectPrimitive.Group key={entry.key}>
                <SelectPrimitive.GroupLabel className="px-2 py-1.5 text-xs text-muted-foreground">{entry.label}</SelectPrimitive.GroupLabel>
                {entry.options.map((option) => <Option key={option.key} option={option} />)}
              </SelectPrimitive.Group>)}
              {model.options.every((option) => option.hidden) && <div className="px-2 py-2 text-sm text-muted-foreground">Нет вариантов</div>}
            </SelectPrimitive.List>
            <SelectPrimitive.ScrollDownArrow className="sticky bottom-0 z-10 flex h-6 items-center justify-center bg-popover text-muted-foreground" aria-hidden="true">⌄</SelectPrimitive.ScrollDownArrow>
          </SelectPrimitive.Popup>
        </SelectPrimitive.Positioner>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
    <select ref={bridge} data-slot="select-event-bridge" hidden aria-hidden="true" tabIndex={-1} value={current ?? (multiple ? [] : "")} multiple={multiple} form={form} disabled={disabled} onChange={onChange ?? (() => {})} onInput={onInput}>
      {model.options.map((option) => <option key={option.key} value={option.value} disabled={option.disabled} hidden={option.hidden}>{option.label}</option>)}
    </select>
  </>;
}
