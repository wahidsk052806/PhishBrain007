import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { resolveBackendEndpoint, type BackendResolution } from "./backend-endpoint";
import { usePhishbrainSettings } from "./usePhishbrainSettings";

/**
 * Shared, app-wide answer to "which engine serves this browser?".
 *
 * One cached query means the header badge, the Analyze page, the Settings page
 * and the history reader all agree, and the probe runs once per backend URL
 * rather than once per component. When the answer arrives, the queries that may
 * already have run against the configured default are invalidated so a LAN
 * visitor does not keep looking at a backend-offline state that was only ever
 * true of their own `localhost`.
 */
export function useBackendEndpoint() {
  const { settings } = usePhishbrainSettings();
  const queryClient = useQueryClient();

  const query = useQuery<BackendResolution>({
    queryKey: ["backend-endpoint", settings.backendUrl],
    queryFn: () => resolveBackendEndpoint(settings),
    retry: false,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const resolvedUrl = query.data?.url ?? null;

  useEffect(() => {
    void queryClient.invalidateQueries({ queryKey: ["health"] });
  }, [resolvedUrl, queryClient]);

  return {
    resolution: query.data,
    isLoading: query.isLoading,
    /** Re-probe now — used by the Settings page's "test connection" action. */
    refresh: () => query.refetch(),
  };
}
