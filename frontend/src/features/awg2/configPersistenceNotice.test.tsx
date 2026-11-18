import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import ConfigPersistenceNotice from "./ConfigPersistenceNotice";

test("Amnezia persistence notices distinguish verified recovery from blocked configuration and escape error text", () => {
  assert.equal(renderToStaticMarkup(<ConfigPersistenceNotice />), "");
  const recovered = renderToStaticMarkup(<ConfigPersistenceNotice recovered />);
  assert.match(recovered, /из проверенной резервной копии/);
  const blocked = renderToStaticMarkup(<ConfigPersistenceNotice error="<script>load failed</script>" recovered />);
  assert.match(blocked, /role="alert"/);
  assert.match(blocked, /Запись остановлена для защиты данных/);
  assert.match(blocked, /&lt;script&gt;load failed&lt;\/script&gt;/);
  assert.doesNotMatch(blocked, /<script>|Настройки Amnezia восстановлены/);
});
