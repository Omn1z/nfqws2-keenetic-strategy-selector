import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { Select } from "./Select";
import { initialSelectValue, normalizeSelectValue, readSelectOptions } from "./selectOptions";

test("select options retain numeric and empty values, labels, arrays, and fragments", () => {
  const model = readSelectOptions(<><option value="">Выберите…</option>{[<option key="zero" value={0}>Ноль</option>, <option key="seconds" value={30}>30 секунд</option>]}<><option> Без явного   значения </option></></>);
  assert.deepEqual(model.options.map(({ value, label }) => [value, label]), [["", "Выберите…"], ["0", "Ноль"], ["30", "30 секунд"], ["Без явного значения", "Без явного значения"]]);
  assert.equal(new Set(model.options.map(({ key }) => key)).size, 4);
  assert.equal(normalizeSelectValue(0, false), "0");
  assert.equal(normalizeSelectValue("", false), "");
});

test("optgroups preserve group names and inherited disabled state without dropping hidden placeholders", () => {
  const model = readSelectOptions(<><option value="" hidden>Выберите сервер</option><optgroup label="Недоступные" disabled><option value="a">A</option></optgroup><optgroup label="Подключения"><option value="b" disabled>B</option><option value="c" label="Короткое имя">Длинное имя</option></optgroup></>);
  assert.equal(model.entries[1].kind, "group");
  assert.deepEqual(model.options.map(({ value, disabled, hidden }) => [value, disabled, hidden]), [["", false, true], ["a", true, false], ["b", true, false], ["c", false, false]]);
  assert.equal(model.options[3].label, "Короткое имя");
});

test("uncontrolled defaults choose the first enabled option, explicit default, or selected option", () => {
  const model = readSelectOptions(<><option value="x" disabled>X</option><option value="a">A</option><option value="b">B</option></>);
  assert.equal(initialSelectValue(undefined, model.options, false), "a");
  assert.equal(initialSelectValue("b", model.options, false), "b");
  assert.equal(initialSelectValue("", model.options, false), "");
  assert.equal(initialSelectValue(undefined, [], false), null);
  const selected = readSelectOptions(<><option value="a">A</option><option value="b" selected>B</option></>);
  assert.equal(initialSelectValue(undefined, selected.options, false), "b");
});

test("multiple values remain arrays and preserve native option selection defaults", () => {
  const model = readSelectOptions(<><option value="a" selected>A</option><option value="b">B</option><option value="c" selected>C</option></>);
  assert.deepEqual(initialSelectValue(undefined, model.options, true), ["a", "c"]);
  assert.deepEqual(initialSelectValue(["b"], model.options, true), ["b"]);
  assert.deepEqual(normalizeSelectValue(0, true), ["0"]);
  assert.deepEqual(normalizeSelectValue(undefined, true), []);
});

test("select renders an accessible custom trigger and exactly one named form field", () => {
  const markup = renderToStaticMarkup(<label>Тип записи<Select id="dns-kind" name="kind" value="AAAA" onChange={() => {}}><option value="A">IPv4</option><option value="AAAA">IPv6</option></Select></label>);
  assert.match(markup, /<button[^>]+role="combobox"/);
  assert.match(markup, /<button[^>]+id="dns-kind"/);
  assert.match(markup, /data-slot="select-value"[^>]*>IPv6<\/span>/);
  assert.equal((markup.match(/name="kind"/g) ?? []).length, 1);
  assert.match(markup, /<select[^>]+data-slot="select-event-bridge"[^>]+hidden=""[^>]+aria-hidden="true"[^>]+tabindex="-1"/);
  assert.match(markup, /<option value="AAAA" selected="">IPv6<\/option>/);
});

test("empty placeholder and numeric controlled values keep their displayed labels", () => {
  const empty = renderToStaticMarkup(<Select value="" aria-label="Резервное подключение"><option value="">Добавить…</option><option value="tunnel">VPN</option></Select>);
  assert.match(empty, /data-slot="select-value"[^>]*>Добавить…<\/span>/);
  const numeric = renderToStaticMarkup(<Select value={25}><option value={10}>10 строк</option><option value={25}>25 строк</option></Select>);
  assert.match(numeric, /data-slot="select-value"[^>]*>25 строк<\/span>/);
});
