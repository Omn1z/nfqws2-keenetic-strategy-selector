import { lazy, Suspense, type ComponentType } from "react";
import { Spinner } from "@/components/ui/Spinner";
import { MissingModule } from "@/components/ui/MissingModule";

function optionalPage(name: string, load: () => Promise<{ default: ComponentType }>) {
  const Page = lazy(() => load().catch(() => ({
    default: () => <MissingModule name={name} />,
  })));
  return () => <Suspense fallback={<Spinner />}><Page /></Suspense>;
}

export const Runs = optionalPage("runs", () => import("@/features/runs/Runs"));
export const BlockCheck = optionalPage("blockcheck", () => import("@/features/blockcheck/BlockCheck"));
export const Strategies = optionalPage("strategies", () => import("@/features/strategies/Strategies"));
export const Geo = optionalPage("geo", () => import("@/features/geo/Geo"));
