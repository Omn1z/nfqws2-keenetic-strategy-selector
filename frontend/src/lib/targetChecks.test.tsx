import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { VerdictBadge } from "@/components/ui/Badge";
import { baselineCheckMessage, summarizeTargetChecks } from "./targetChecks";

test("Local probe failures are inconclusive and do not advertise reachability", () => {
  const checks = [{ blocked: false, verdict: "local_error" as const }];
  assert.deepEqual(summarizeTargetChecks(checks), { blocked: 0, localErrors: 1 });
  assert.match(baselineCheckMessage(checks), /доступность не определена/);
  assert.doesNotMatch(baselineCheckMessage(checks), /всё доступно|Обходить нечего/);
  const html = renderToStaticMarkup(<VerdictBadge v="local_error" />);
  assert.match(html, /локальная ошибка/);
  assert.match(html, /text-warn/);
  assert.doesNotMatch(html, /text-ok|text-bad|доступен/);
});

test("Mixed baseline keeps local failures separate from successful and blocked targets", () => {
  const checks = [
    { blocked: false, verdict: "ok" as const },
    { blocked: true, verdict: "reset" as const },
    { blocked: false, verdict: "local_error" as const },
    // The explicit local verdict takes precedence over a conflicting flag.
    { blocked: true, verdict: "local_error" as const },
  ];
  assert.deepEqual(summarizeTargetChecks(checks), { blocked: 1, localErrors: 2 });
  assert.match(baselineCheckMessage(checks), /у 2 целей/);
  assert.doesNotMatch(baselineCheckMessage(checks), /всё доступно/);
});

test("Successful and blocked baselines keep their existing descriptions", () => {
  assert.match(baselineCheckMessage([{ blocked: false, verdict: "ok" }]), /всё доступно/);
  assert.match(baselineCheckMessage([{ blocked: true, verdict: "timeout" }]), /только на заблокированных/);
});
